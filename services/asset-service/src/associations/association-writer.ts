import {
  ASSET_EVENT_TYPES,
  cveAssociationChangedPayloadSchema,
  versionRangeKey,
  type AffectedStatus,
  type AssociationOrigin,
  type DomainEventEnvelope,
  type ProductHistoryChange,
  type VersionRange,
  type VersionRangeInput,
} from '@cve/contracts';

import type { ActorContext } from '../common/request-context.js';
import { assetEvent } from '../events/asset-events.js';
import { toDbHistoryChange } from '../catalog/mapping.js';
import {
  refreshProductCounters,
  refreshVendorCounters,
  type Prisma,
  type Tx,
} from '../persistence/database.js';

/** The association a source currently reports for one CVE and product. */
export interface DesiredAssociation {
  readonly cveId: string;
  readonly productId: string;
  readonly ranges: readonly VersionRangeInput[];
}

export interface AssociationSet {
  readonly source: string;
  readonly sourceRecordId: string;
  readonly origin: AssociationOrigin;
  readonly sourceUrl: string | null;
  readonly attribution: string | null;
  readonly note?: string | null;
  /**
   * Existing associations the set replaces: those not in `desired` are withdrawn. Always
   * narrower than or equal to `{ source, sourceRecordId }`.
   */
  readonly scope: Prisma.CveProductAssociationWhereInput;
  readonly desired: readonly DesiredAssociation[];
  readonly seenAt: Date;
}

export interface AssociationChange {
  readonly associationId: string;
  readonly cveId: string;
  readonly productId: string;
  readonly change: ProductHistoryChange;
}

/** `affected` if any range is affected, else `unknown` if any is unknown, else `unaffected`. */
export function associationStatus(ranges: readonly { status: AffectedStatus }[]): AffectedStatus {
  if (ranges.some((range) => range.status === 'affected')) return 'affected';
  if (ranges.some((range) => range.status === 'unknown')) return 'unknown';
  return 'unaffected';
}

/** Removes duplicate ranges and sorts them, so equal sets compare equal. */
export function canonicalRanges(ranges: readonly VersionRangeInput[]): VersionRangeInput[] {
  const byKey = new Map<string, VersionRangeInput>();
  for (const range of ranges) byKey.set(versionRangeKey(range), range);
  return [...byKey.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, range]) => range);
}

export function toVersionRange(range: VersionRangeInput): VersionRange {
  return {
    status: range.status,
    cpe: range.cpe ?? null,
    version: range.version ?? null,
    versionStartIncluding: range.versionStartIncluding ?? null,
    versionStartExcluding: range.versionStartExcluding ?? null,
    versionEndIncluding: range.versionEndIncluding ?? null,
    versionEndExcluding: range.versionEndExcluding ?? null,
  };
}

export function fromStoredRange(row: {
  status: AffectedStatus;
  cpe: string | null;
  version: string | null;
  versionStartIncluding: string | null;
  versionStartExcluding: string | null;
  versionEndIncluding: string | null;
  versionEndExcluding: string | null;
}): VersionRangeInput {
  return {
    status: row.status,
    ...(row.cpe === null ? {} : { cpe: row.cpe }),
    ...(row.version === null ? {} : { version: row.version }),
    ...(row.versionStartIncluding === null
      ? {}
      : { versionStartIncluding: row.versionStartIncluding }),
    ...(row.versionStartExcluding === null
      ? {}
      : { versionStartExcluding: row.versionStartExcluding }),
    ...(row.versionEndIncluding === null ? {} : { versionEndIncluding: row.versionEndIncluding }),
    ...(row.versionEndExcluding === null ? {} : { versionEndExcluding: row.versionEndExcluding }),
  };
}

const sameRanges = (a: readonly VersionRangeInput[], b: readonly VersionRangeInput[]) =>
  JSON.stringify(canonicalRanges(a).map(versionRangeKey)) ===
  JSON.stringify(canonicalRanges(b).map(versionRangeKey));

const associationKey = (cveId: string, productId: string) => `${cveId}|${productId}`;

const EVENT_TYPE_FOR_CHANGE: Readonly<Record<ProductHistoryChange, string>> = {
  added: ASSET_EVENT_TYPES.associationAdded,
  restored: ASSET_EVENT_TYPES.associationAdded,
  'ranges-changed': ASSET_EVENT_TYPES.associationUpdated,
  withdrawn: ASSET_EVENT_TYPES.associationWithdrawn,
};

/**
 * Reconciles the stored associations of one source item with what it reports now, inside the
 * caller's transaction: new ones are added, changed ranges replaced, missing ones withdrawn and
 * reappearing ones restored. Every change is appended to the product vulnerability history and
 * produces an `asset.cve-association.*` event; product and vendor counters are recomputed.
 */
export async function applyAssociationSet(
  tx: Tx,
  set: AssociationSet,
  context: ActorContext,
): Promise<{ changes: AssociationChange[]; events: DomainEventEnvelope[] }> {
  const existing = await tx.cveProductAssociation.findMany({
    where: { AND: [{ source: set.source, sourceRecordId: set.sourceRecordId }, set.scope] },
    include: { ranges: true },
  });
  const byKey = new Map(existing.map((row) => [associationKey(row.cveId, row.productId), row]));
  const desiredKeys = new Set<string>();
  const productIds = new Set<string>();
  const changes: AssociationChange[] = [];
  const events: DomainEventEnvelope[] = [];

  const products = await tx.product.findMany({
    where: {
      id: {
        in: [
          ...new Set([...set.desired.map((d) => d.productId), ...existing.map((e) => e.productId)]),
        ],
      },
    },
    select: { id: true, slug: true, vendorId: true, vendor: { select: { slug: true } } },
  });
  const productById = new Map(products.map((product) => [product.id, product]));

  const record = async (
    associationId: string,
    cveId: string,
    productId: string,
    change: ProductHistoryChange,
    ranges: readonly VersionRangeInput[],
  ) => {
    const product = productById.get(productId);
    if (!product) throw new Error(`product ${productId} disappeared during the transaction`);
    const views = canonicalRanges(ranges).map(toVersionRange);
    await tx.productVulnerabilityHistory.create({
      data: {
        productId,
        associationId,
        cveId,
        change: toDbHistoryChange(change),
        source: set.source,
        sourceRecordId: set.sourceRecordId,
        ranges: views,
        occurredAt: set.seenAt,
      },
    });
    events.push(
      assetEvent(
        EVENT_TYPE_FOR_CHANGE[change],
        cveAssociationChangedPayloadSchema,
        {
          associationId,
          cveId,
          productId,
          productSlug: product.slug,
          vendorId: product.vendorId,
          vendorSlug: product.vendor.slug,
          source: set.source,
          sourceRecordId: set.sourceRecordId,
          origin: set.origin,
          change,
          status: associationStatus(ranges),
          ranges: views,
          actor: context.actor,
        },
        context,
      ),
    );
    changes.push({ associationId, cveId, productId, change });
    productIds.add(productId);
  };

  const writeRanges = async (associationId: string, ranges: readonly VersionRangeInput[]) => {
    await tx.affectedVersionRange.deleteMany({ where: { associationId } });
    await tx.affectedVersionRange.createMany({
      data: canonicalRanges(ranges).map((range) => ({
        associationId,
        rangeKey: versionRangeKey(range),
        ...toVersionRange(range),
      })),
    });
  };

  for (const desired of set.desired) {
    const key = associationKey(desired.cveId, desired.productId);
    if (desiredKeys.has(key)) throw new Error(`duplicate desired association ${key}`);
    desiredKeys.add(key);
    const product = productById.get(desired.productId);
    if (!product) throw new Error(`product ${desired.productId} does not exist`);
    const status = associationStatus(desired.ranges);
    const current = byKey.get(key);
    const common = {
      status,
      sourceUrl: set.sourceUrl,
      attribution: set.attribution,
      lastSeenAt: set.seenAt,
      ...(set.note === undefined ? {} : { note: set.note }),
    };

    if (!current) {
      const created = await tx.cveProductAssociation.create({
        data: {
          cveId: desired.cveId,
          productId: desired.productId,
          vendorId: product.vendorId,
          source: set.source,
          sourceRecordId: set.sourceRecordId,
          origin: set.origin,
          firstSeenAt: set.seenAt,
          ...common,
        },
      });
      await writeRanges(created.id, desired.ranges);
      await record(created.id, desired.cveId, desired.productId, 'added', desired.ranges);
      continue;
    }

    const stored = current.ranges.map(fromStoredRange);
    const rangesChanged = !sameRanges(stored, desired.ranges);
    await tx.cveProductAssociation.update({
      where: { id: current.id },
      data: {
        ...common,
        // Never move lastSeenAt backwards (the CHECK constraint keeps it >= firstSeenAt).
        lastSeenAt: current.lastSeenAt > set.seenAt ? current.lastSeenAt : set.seenAt,
        withdrawnAt: null,
      },
    });
    if (rangesChanged) await writeRanges(current.id, desired.ranges);
    if (current.withdrawnAt !== null) {
      await record(current.id, desired.cveId, desired.productId, 'restored', desired.ranges);
    } else if (rangesChanged) {
      await record(current.id, desired.cveId, desired.productId, 'ranges-changed', desired.ranges);
    }
  }

  for (const row of existing) {
    if (row.withdrawnAt !== null || desiredKeys.has(associationKey(row.cveId, row.productId))) {
      continue;
    }
    await tx.cveProductAssociation.update({
      where: { id: row.id },
      data: { withdrawnAt: set.seenAt },
    });
    await record(row.id, row.cveId, row.productId, 'withdrawn', row.ranges.map(fromStoredRange));
  }

  if (productIds.size > 0) {
    await refreshProductCounters(tx, [...productIds]);
    const vendorIds = new Set(
      [...productIds].map((id) => productById.get(id)?.vendorId).filter((id) => id !== undefined),
    );
    await refreshVendorCounters(tx, [...vendorIds]);
  }
  return { changes, events };
}
