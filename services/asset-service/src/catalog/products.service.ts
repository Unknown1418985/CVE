import { Inject, Injectable } from '@nestjs/common';

import {
  ASSET_EVENT_TYPES,
  parseCpe23,
  productCreatedPayloadSchema,
  productDeletedPayloadSchema,
  productTypeForCpePart,
  productUpdatedPayloadSchema,
  PRODUCT_CHANGE_FIELDS,
  slugify,
  type CreateProductRequest,
  type ListProductsQuery,
  type Product,
  type ProductCpeInput,
  type ProductIdentifierInput,
  type ProductSummary,
  type UpdateProductRequest,
} from '@cve/contracts';
import type { Logger } from '@cve/logger';

import {
  badField,
  checkPrecondition,
  conflict,
  notFound,
  type Precondition,
} from '../common/http.js';
import { APP_LOGGER } from '../common/lifecycle.js';
import type { ActorContext } from '../common/request-context.js';
import { assetEvent } from '../events/asset-events.js';
import type { PrismaClient } from '../generated/prisma/client.js';
import {
  escapeLike,
  isUniqueViolation,
  outboxRows,
  PRISMA,
  refreshVendorCounters,
  type Prisma,
  type Tx,
} from '../persistence/database.js';
import {
  productInclude,
  toDbIdentifierType,
  toDbProductType,
  toProduct,
  toProductSummary,
  type ProductRow,
} from './mapping.js';

export type ProductChangeField = (typeof PRODUCT_CHANGE_FIELDS)[number];

export function productSnapshot(row: ProductRow) {
  return {
    productId: row.id,
    slug: row.slug,
    name: row.name,
    type: toProduct(row).type,
    origin: row.origin,
    source: row.source,
    vendorId: row.vendor.id,
    vendorSlug: row.vendor.slug,
    cpes: row.cpes.map((cpe) => cpe.cpe),
    version: row.version,
  };
}

/** Outcome of registering a CPE name for a product. */
export type CpeRegistration = 'created' | 'already-registered' | 'taken';

/** Registers a CPE 2.3 name; a name belongs to at most one product. */
export async function registerCpe(
  tx: Tx,
  productId: string,
  cpe: string,
  source: string,
): Promise<CpeRegistration> {
  const parts = parseCpe23(cpe);
  if (parts === null) throw badField('cpe', 'must be a CPE 2.3 formatted string');
  const normalized = cpe.trim().toLowerCase();
  const existing = await tx.productCpe.findUnique({ where: { cpe: normalized } });
  if (existing) return existing.productId === productId ? 'already-registered' : 'taken';
  await tx.productCpe.create({
    data: {
      productId,
      cpe: normalized,
      part: parts.part,
      cpeVendor: parts.vendor,
      cpeProduct: parts.product,
      cpeVersion: parts.version,
      source,
    },
  });
  return 'created';
}

/** Registers a product identifier; each (type, value) belongs to at most one product. */
export async function registerIdentifier(
  tx: Tx,
  productId: string,
  input: ProductIdentifierInput,
): Promise<CpeRegistration> {
  const type = toDbIdentifierType(input.type);
  const existing = await tx.productIdentifier.findUnique({
    where: { type_value: { type, value: input.value } },
  });
  if (existing) return existing.productId === productId ? 'already-registered' : 'taken';
  await tx.productIdentifier.create({
    data: { productId, type, value: input.value, source: input.source },
  });
  return 'created';
}

/** Products registered with a CPE name of the same part, vendor and product (wildcards match). */
export function cpeMatchWhere(cpe: string): Prisma.ProductCpeWhereInput | null {
  const parts = parseCpe23(cpe);
  if (parts === null) return null;
  return {
    ...(parts.vendor === '*' ? {} : { cpeVendor: parts.vendor }),
    ...(parts.product === '*' ? {} : { cpeProduct: parts.product }),
    ...(parts.part === '*' ? {} : { part: { in: [parts.part, '*'] } }),
  };
}

function productOrder(query: ListProductsQuery): Prisma.ProductOrderByWithRelationInput[] {
  const tie: Prisma.ProductOrderByWithRelationInput = { id: query.order };
  switch (query.sort) {
    case 'name':
      return [{ name: query.order }, { slug: query.order }, tie];
    case 'createdAt':
      return [{ createdAt: query.order }, tie];
    case 'updatedAt':
      return [{ updatedAt: query.order }, tie];
    case 'cveCount':
      return [{ cveCount: query.order }, tie];
  }
}

/** Product catalog with CPE names and other identifiers (`asset.product.*` events). */
@Injectable()
export class ProductsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClient,
    @Inject(APP_LOGGER) private readonly logger: Logger,
  ) {}

  async list(query: ListProductsQuery): Promise<{ items: ProductSummary[]; total: number }> {
    const and: Prisma.ProductWhereInput[] = [];
    if (query.q !== undefined) {
      const q = escapeLike(query.q);
      and.push({
        OR: [
          { name: { contains: q, mode: 'insensitive' } },
          { slug: { contains: q.toLowerCase() } },
        ],
      });
    }
    if (query.vendorId !== undefined) and.push({ vendorId: query.vendorId });
    if (query.vendor !== undefined) and.push({ vendor: { slug: query.vendor } });
    if (query.type !== undefined) and.push({ type: toDbProductType(query.type) });
    if (query.origin !== undefined) and.push({ origin: query.origin });
    if (query.cpe !== undefined) {
      const match = cpeMatchWhere(query.cpe);
      if (match) and.push({ cpes: { some: match } });
    }
    if (query.identifier !== undefined) {
      and.push({ identifiers: { some: { value: query.identifier } } });
    }
    const where: Prisma.ProductWhereInput = and.length === 0 ? {} : { AND: and };
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.product.findMany({
        where,
        include: { vendor: { select: { id: true, slug: true, name: true } } },
        orderBy: productOrder(query),
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.product.count({ where }),
    ]);
    return { items: rows.map(toProductSummary), total };
  }

  async get(productId: string): Promise<Product> {
    return toProduct(await this.require(this.prisma, productId));
  }

  async create(context: ActorContext, input: CreateProductRequest): Promise<Product> {
    const slug = input.slug ?? slugify(input.name);
    if (slug === null) throw badField('slug', 'cannot be derived from the name; supply a slug');
    const firstCpe = input.cpes[0] ? parseCpe23(input.cpes[0].cpe) : null;
    const type =
      input.type === 'unknown' && firstCpe ? productTypeForCpePart(firstCpe.part) : input.type;
    try {
      const row = await this.prisma.$transaction(async (tx) => {
        const vendor = await tx.vendor.findUnique({ where: { id: input.vendorId } });
        if (!vendor) throw badField('vendorId', 'vendor does not exist');
        const created = await tx.product.create({
          data: {
            vendorId: vendor.id,
            slug,
            name: input.name,
            type: toDbProductType(type),
            description: input.description,
            website: input.website,
            source: input.source,
            origin: 'curated',
          },
        });
        for (const [index, cpe] of input.cpes.entries()) {
          if ((await registerCpe(tx, created.id, cpe.cpe, cpe.source)) === 'taken') {
            throw conflict(
              'The CPE name is registered to another product',
              `cpes.${String(index)}`,
            );
          }
        }
        for (const [index, identifier] of input.identifiers.entries()) {
          if ((await registerIdentifier(tx, created.id, identifier)) === 'taken') {
            throw conflict(
              'The identifier is registered to another product',
              `identifiers.${String(index)}`,
            );
          }
        }
        await refreshVendorCounters(tx, [vendor.id]);
        const full = await this.require(tx, created.id);
        await tx.outboxEvent.createMany({
          data: outboxRows([
            assetEvent(
              ASSET_EVENT_TYPES.productCreated,
              productCreatedPayloadSchema,
              { ...productSnapshot(full), actor: context.actor },
              context,
            ),
          ]),
        });
        return full;
      });
      this.logger.info({ productId: row.id, vendorId: row.vendorId, slug }, 'product created');
      return toProduct(row);
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw conflict(`The vendor already has a product with slug "${slug}"`, 'slug');
      }
      throw error;
    }
  }

  async update(
    context: ActorContext,
    productId: string,
    patch: UpdateProductRequest,
    precondition: Precondition,
  ): Promise<{ product: Product; changed: boolean }> {
    const current = await this.require(this.prisma, productId);
    checkPrecondition(precondition, current.version);
    const view = toProduct(current);
    const changedFields: ProductChangeField[] = [];
    if (patch.name !== undefined && patch.name !== current.name) changedFields.push('name');
    if (patch.type !== undefined && patch.type !== view.type) changedFields.push('type');
    if (patch.description !== undefined && patch.description !== current.description) {
      changedFields.push('description');
    }
    if (patch.website !== undefined && patch.website !== current.website) {
      changedFields.push('website');
    }
    if (changedFields.length === 0) return { product: view, changed: false };
    if (current.origin === 'discovered') changedFields.push('origin');

    const row = await this.mutate(context, current, changedFields, async (tx) => {
      await tx.product.update({
        where: { id: productId },
        data: {
          ...(patch.name === undefined ? {} : { name: patch.name }),
          ...(patch.type === undefined ? {} : { type: toDbProductType(patch.type) }),
          ...(patch.description === undefined ? {} : { description: patch.description }),
          ...(patch.website === undefined ? {} : { website: patch.website }),
          origin: 'curated',
        },
      });
      return true;
    });
    return { product: toProduct(row), changed: true };
  }

  /** Deletes a product. Products with CVE associations are kept so their history survives. */
  async delete(
    context: ActorContext,
    productId: string,
    precondition: Precondition,
  ): Promise<void> {
    const current = await this.require(this.prisma, productId);
    checkPrecondition(precondition, current.version);
    await this.prisma.$transaction(async (tx) => {
      const associations = await tx.cveProductAssociation.count({ where: { productId } });
      if (associations > 0) {
        throw conflict(
          `The product has ${String(associations)} CVE association(s) and cannot be deleted`,
        );
      }
      const { count } = await tx.product.deleteMany({
        where: { id: productId, version: current.version },
      });
      if (count === 0) throw conflict('The product was modified concurrently; retry');
      await refreshVendorCounters(tx, [current.vendorId]);
      await tx.outboxEvent.createMany({
        data: outboxRows([
          assetEvent(
            ASSET_EVENT_TYPES.productDeleted,
            productDeletedPayloadSchema,
            { ...productSnapshot(current), actor: context.actor },
            context,
          ),
        ]),
      });
    });
    this.logger.info({ productId, slug: current.slug }, 'product deleted');
  }

  async addCpe(
    context: ActorContext,
    productId: string,
    input: ProductCpeInput,
  ): Promise<{ product: Product; changed: boolean }> {
    const current = await this.require(this.prisma, productId);
    const state: { outcome: CpeRegistration } = { outcome: 'already-registered' };
    const row = await this.mutate(context, current, ['cpes'], async (tx) => {
      state.outcome = await registerCpe(tx, productId, input.cpe, input.source);
      if (state.outcome === 'taken') {
        throw conflict('The CPE name is registered to another product', 'cpe');
      }
      return state.outcome === 'created';
    });
    return { product: toProduct(row), changed: state.outcome === 'created' };
  }

  async removeCpe(context: ActorContext, productId: string, cpeId: string): Promise<Product> {
    const current = await this.require(this.prisma, productId);
    if (!current.cpes.some((cpe) => cpe.id === cpeId)) {
      throw notFound(`CPE ${cpeId} is not registered for product ${productId}`);
    }
    const row = await this.mutate(context, current, ['cpes'], async (tx) => {
      await tx.productCpe.delete({ where: { id: cpeId } });
      return true;
    });
    return toProduct(row);
  }

  async addIdentifier(
    context: ActorContext,
    productId: string,
    input: ProductIdentifierInput,
  ): Promise<{ product: Product; changed: boolean }> {
    const current = await this.require(this.prisma, productId);
    const state: { outcome: CpeRegistration } = { outcome: 'already-registered' };
    const row = await this.mutate(context, current, ['identifiers'], async (tx) => {
      state.outcome = await registerIdentifier(tx, productId, input);
      if (state.outcome === 'taken') {
        throw conflict('The identifier is registered to another product', 'value');
      }
      return state.outcome === 'created';
    });
    return { product: toProduct(row), changed: state.outcome === 'created' };
  }

  async removeIdentifier(
    context: ActorContext,
    productId: string,
    identifierId: string,
  ): Promise<Product> {
    const current = await this.require(this.prisma, productId);
    if (!current.identifiers.some((identifier) => identifier.id === identifierId)) {
      throw notFound(`Identifier ${identifierId} does not belong to product ${productId}`);
    }
    const row = await this.mutate(context, current, ['identifiers'], async (tx) => {
      await tx.productIdentifier.delete({ where: { id: identifierId } });
      return true;
    });
    return toProduct(row);
  }

  /**
   * Runs a change in a transaction, bumps the product version (optimistic check against the
   * version read before) and writes `asset.product.updated`. `change` returns `false` when
   * nothing changed; the transaction is then rolled back.
   */
  private async mutate(
    context: ActorContext,
    current: ProductRow,
    changedFields: ProductChangeField[],
    change: (tx: Tx) => Promise<boolean>,
  ): Promise<ProductRow> {
    const row = await this.prisma
      .$transaction(async (tx) => {
        const { count } = await tx.product.updateMany({
          where: { id: current.id, version: current.version },
          data: { version: { increment: 1 } },
        });
        if (count === 0) throw conflict('The product was modified concurrently; retry');
        if (!(await change(tx))) {
          // Nothing changed: undo the version bump by aborting the transaction.
          throw new UnchangedSignal();
        }
        const updated = await this.require(tx, current.id);
        await tx.outboxEvent.createMany({
          data: outboxRows([
            assetEvent(
              ASSET_EVENT_TYPES.productUpdated,
              productUpdatedPayloadSchema,
              { ...productSnapshot(updated), actor: context.actor, changedFields },
              context,
            ),
          ]),
        });
        return updated;
      })
      .catch((error: unknown) => {
        if (error instanceof UnchangedSignal) return null;
        throw error;
      });
    if (row === null) return current;
    this.logger.info({ productId: current.id, changedFields }, 'product updated');
    return row;
  }

  private async require(db: PrismaClient | Tx, productId: string): Promise<ProductRow> {
    const row = await db.product.findUnique({ where: { id: productId }, include: productInclude });
    if (!row) throw notFound(`Product ${productId} not found`);
    return row;
  }
}

/** Internal control flow: rolls back a transaction that turned out to change nothing. */
class UnchangedSignal extends Error {
  constructor() {
    super('unchanged');
    this.name = 'UnchangedSignal';
  }
}
