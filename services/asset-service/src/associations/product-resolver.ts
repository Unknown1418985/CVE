import {
  ASSET_EVENT_TYPES,
  cpe23ProductName,
  parseCpe23,
  productCreatedPayloadSchema,
  productTypeForCpePart,
  slugify,
  vendorCreatedPayloadSchema,
  type DomainEventEnvelope,
  type ProductType,
} from '@cve/contracts';

import { productSnapshot, registerCpe, registerIdentifier } from '../catalog/products.service.js';
import { productInclude, toDbProductType } from '../catalog/mapping.js';
import { vendorSnapshot } from '../catalog/vendors.service.js';
import type { ActorContext } from '../common/request-context.js';
import { assetEvent } from '../events/asset-events.js';
import type { Tx } from '../persistence/database.js';

/** Vendor names sources use when they do not know the vendor. Such entries are not catalogued. */
const PLACEHOLDER_VENDORS = new Set(['', 'n/a', 'na', 'unknown', 'none', '-', '*']);

/**
 * GitHub advisory ecosystems → Package URL types (https://github.com/package-url/purl-spec).
 * Ecosystems not listed get no Package URL.
 */
const PURL_TYPES: Readonly<Record<string, string>> = {
  npm: 'npm',
  pip: 'pypi',
  maven: 'maven',
  nuget: 'nuget',
  go: 'golang',
  rubygems: 'gem',
  composer: 'composer',
  rust: 'cargo',
  erlang: 'hex',
  pub: 'pub',
  swift: 'swift',
  actions: 'github',
};

/** Package URL (without version) of a package in a GitHub advisory ecosystem, if known. */
export function packageUrl(ecosystem: string, name: string): string | null {
  const type = PURL_TYPES[ecosystem.trim().toLowerCase()];
  if (type === undefined) return null;
  const trimmed = name.trim();
  if (trimmed === '' || /[\s?#@]/.test(trimmed.replace(/^@/, ''))) return null;
  let path: string;
  if (type === 'maven') {
    // GitHub writes Maven coordinates as `group:artifact`.
    const [group, artifact, ...rest] = trimmed.split(':');
    if (!group || !artifact || rest.length > 0) return null;
    path = `${encodeURIComponent(group)}/${encodeURIComponent(artifact)}`;
  } else if (type === 'pypi') {
    // PEP 503 normalisation, as the purl spec requires for PyPI.
    path = encodeURIComponent(trimmed.toLowerCase().replace(/[-_.]+/g, '-'));
  } else {
    path = trimmed
      .split('/')
      .map((segment) => encodeURIComponent(segment))
      .join('/');
  }
  return `pkg:${type}/${path}`;
}

/** An affected-product entry as reported by a source (CVE Service write model). */
export interface ObservedProduct {
  readonly vendor: string;
  readonly product: string;
  readonly cpe?: string | undefined;
}

export type Resolution =
  | { readonly kind: 'resolved'; readonly productId: string; readonly vendorId: string }
  | { readonly kind: 'skipped'; readonly reason: string };

/**
 * Maps affected-product entries from CVE data onto catalog products, creating `discovered`
 * vendors and products for entries the catalog does not know yet:
 *
 * 1. a registered CPE name with the same part, vendor and product;
 * 2. a registered Package URL (GitHub advisories: ecosystem + package name);
 * 3. vendor and product slugs derived from the names;
 * 4. otherwise a new discovered vendor and/or product, with the product's base CPE name and
 *    Package URL registered when they are not taken.
 *
 * Results are cached per instance; create one resolver per transaction.
 */
export class ProductResolver {
  private readonly cache = new Map<string, Resolution>();
  readonly events: DomainEventEnvelope[] = [];

  constructor(
    private readonly tx: Tx,
    private readonly source: string,
    private readonly context: ActorContext,
  ) {}

  async resolve(entry: ObservedProduct): Promise<Resolution> {
    const cpe = entry.cpe === undefined ? null : parseCpe23(entry.cpe);
    const purl = this.source === 'github-advisory' ? packageUrl(entry.vendor, entry.product) : null;
    const key = JSON.stringify([
      entry.vendor.trim().toLowerCase(),
      entry.product.trim().toLowerCase(),
      cpe?.part ?? null,
      cpe?.vendor ?? null,
      cpe?.product ?? null,
    ]);
    const cached = this.cache.get(key);
    if (cached) return cached;
    const resolution = await this.lookupOrCreate(entry, cpe, purl);
    this.cache.set(key, resolution);
    return resolution;
  }

  private async lookupOrCreate(
    entry: ObservedProduct,
    cpe: ReturnType<typeof parseCpe23>,
    purl: string | null,
  ): Promise<Resolution> {
    const { tx } = this;
    const usableCpe = cpe && cpe.vendor !== '*' && cpe.product !== '*' ? cpe : null;

    if (usableCpe) {
      const match = await tx.productCpe.findFirst({
        where: {
          cpeVendor: usableCpe.vendor,
          cpeProduct: usableCpe.product,
          part: { in: [usableCpe.part, '*'] },
        },
        orderBy: { createdAt: 'asc' },
        select: { product: { select: { id: true, vendorId: true } } },
      });
      if (match) return resolved(match.product);
    }
    if (purl) {
      const match = await tx.productIdentifier.findUnique({
        where: { type_value: { type: 'purl', value: purl } },
        select: { product: { select: { id: true, vendorId: true } } },
      });
      if (match) return resolved(match.product);
    }

    if (PLACEHOLDER_VENDORS.has(entry.vendor.trim().toLowerCase())) {
      return { kind: 'skipped', reason: `placeholder vendor "${entry.vendor}"` };
    }
    const vendorSlug = slugify(entry.vendor) ?? (usableCpe ? slugify(usableCpe.vendor) : null);
    const productSlug = slugify(entry.product) ?? (usableCpe ? slugify(usableCpe.product) : null);
    if (vendorSlug === null || productSlug === null) {
      return { kind: 'skipped', reason: 'no slug can be derived from the vendor or product name' };
    }

    let vendor = await tx.vendor.findUnique({ where: { slug: vendorSlug } });
    if (!vendor) {
      vendor = await tx.vendor.create({
        data: {
          slug: vendorSlug,
          name: entry.vendor.trim().slice(0, 128),
          origin: 'discovered',
          source: this.source,
        },
      });
      this.events.push(
        assetEvent(
          ASSET_EVENT_TYPES.vendorCreated,
          vendorCreatedPayloadSchema,
          { ...vendorSnapshot(vendor), actor: this.context.actor },
          this.context,
        ),
      );
    }

    const existing = await tx.product.findUnique({
      where: { vendorId_slug: { vendorId: vendor.id, slug: productSlug } },
      select: { id: true, vendorId: true },
    });
    if (existing) return resolved(existing);

    const type: ProductType = usableCpe
      ? productTypeForCpePart(usableCpe.part)
      : purl
        ? 'application'
        : 'unknown';
    const created = await tx.product.create({
      data: {
        vendorId: vendor.id,
        slug: productSlug,
        name: entry.product.trim().slice(0, 128),
        type: toDbProductType(type),
        origin: 'discovered',
        source: this.source,
      },
    });
    if (usableCpe) await registerCpe(tx, created.id, cpe23ProductName(usableCpe), this.source);
    if (purl) {
      await registerIdentifier(tx, created.id, { type: 'purl', value: purl, source: this.source });
    }
    const full = await tx.product.findUniqueOrThrow({
      where: { id: created.id },
      include: productInclude,
    });
    this.events.push(
      assetEvent(
        ASSET_EVENT_TYPES.productCreated,
        productCreatedPayloadSchema,
        { ...productSnapshot(full), actor: this.context.actor },
        this.context,
      ),
    );
    return resolved(created);
  }
}

function resolved(product: { id: string; vendorId: string }): Resolution {
  return { kind: 'resolved', productId: product.id, vendorId: product.vendorId };
}
