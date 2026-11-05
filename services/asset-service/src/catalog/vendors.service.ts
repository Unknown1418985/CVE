import { Inject, Injectable } from '@nestjs/common';

import {
  ASSET_EVENT_TYPES,
  slugify,
  vendorCreatedPayloadSchema,
  vendorDeletedPayloadSchema,
  vendorUpdatedPayloadSchema,
  VENDOR_CHANGE_FIELDS,
  type CreateVendorRequest,
  type ListVendorsQuery,
  type UpdateVendorRequest,
  type Vendor,
} from '@cve/contracts';
import type { Logger } from '@cve/logger';

import {
  checkPrecondition,
  conflict,
  badField,
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
  type Prisma,
  type Tx,
} from '../persistence/database.js';
import { toVendor, type VendorRow } from './mapping.js';

type VendorChangeField = (typeof VENDOR_CHANGE_FIELDS)[number];

export function vendorSnapshot(row: VendorRow) {
  return {
    vendorId: row.id,
    slug: row.slug,
    name: row.name,
    origin: row.origin,
    source: row.source,
    version: row.version,
  };
}

function vendorOrder(query: ListVendorsQuery): Prisma.VendorOrderByWithRelationInput[] {
  const tie: Prisma.VendorOrderByWithRelationInput = { id: query.order };
  switch (query.sort) {
    case 'name':
      return [{ name: query.order }, { slug: query.order }, tie];
    case 'createdAt':
      return [{ createdAt: query.order }, tie];
    case 'updatedAt':
      return [{ updatedAt: query.order }, tie];
    case 'productCount':
      return [{ productCount: query.order }, tie];
    case 'cveCount':
      return [{ cveCount: query.order }, tie];
  }
}

/** Vendor catalog. Writes go through the transactional outbox (`asset.vendor.*`). */
@Injectable()
export class VendorsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClient,
    @Inject(APP_LOGGER) private readonly logger: Logger,
  ) {}

  async list(query: ListVendorsQuery): Promise<{ items: Vendor[]; total: number }> {
    const and: Prisma.VendorWhereInput[] = [];
    if (query.q !== undefined) {
      const q = escapeLike(query.q);
      and.push({
        OR: [
          { name: { contains: q, mode: 'insensitive' } },
          { slug: { contains: q.toLowerCase() } },
        ],
      });
    }
    if (query.origin !== undefined) and.push({ origin: query.origin });
    const where: Prisma.VendorWhereInput = and.length === 0 ? {} : { AND: and };
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.vendor.findMany({
        where,
        orderBy: vendorOrder(query),
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.vendor.count({ where }),
    ]);
    return { items: rows.map(toVendor), total };
  }

  async get(vendorId: string): Promise<Vendor> {
    return toVendor(await this.require(this.prisma, vendorId));
  }

  async create(context: ActorContext, input: CreateVendorRequest): Promise<Vendor> {
    const slug = input.slug ?? slugify(input.name);
    if (slug === null) {
      throw badField('slug', 'cannot be derived from the name; supply a slug');
    }
    try {
      const row = await this.prisma.$transaction(async (tx) => {
        const created = await tx.vendor.create({
          data: {
            slug,
            name: input.name,
            description: input.description,
            website: input.website,
            source: input.source,
            origin: 'curated',
          },
        });
        await tx.outboxEvent.createMany({
          data: outboxRows([
            assetEvent(
              ASSET_EVENT_TYPES.vendorCreated,
              vendorCreatedPayloadSchema,
              { ...vendorSnapshot(created), actor: context.actor },
              context,
            ),
          ]),
        });
        return created;
      });
      this.logger.info({ vendorId: row.id, slug }, 'vendor created');
      return toVendor(row);
    } catch (error) {
      if (isUniqueViolation(error)) throw conflict(`A vendor with slug "${slug}" exists`, 'slug');
      throw error;
    }
  }

  async update(
    context: ActorContext,
    vendorId: string,
    patch: UpdateVendorRequest,
    precondition: Precondition,
  ): Promise<{ vendor: Vendor; changed: boolean }> {
    const current = await this.require(this.prisma, vendorId);
    checkPrecondition(precondition, current.version);
    const changedFields: VendorChangeField[] = [];
    if (patch.name !== undefined && patch.name !== current.name) changedFields.push('name');
    if (patch.description !== undefined && patch.description !== current.description) {
      changedFields.push('description');
    }
    if (patch.website !== undefined && patch.website !== current.website) {
      changedFields.push('website');
    }
    if (changedFields.length === 0) return { vendor: toVendor(current), changed: false };
    // A discovered vendor that an analyst edits becomes curated.
    if (current.origin === 'discovered') changedFields.push('origin');

    const row = await this.prisma.$transaction(async (tx) => {
      const { count } = await tx.vendor.updateMany({
        where: { id: vendorId, version: current.version },
        data: {
          ...(patch.name === undefined ? {} : { name: patch.name }),
          ...(patch.description === undefined ? {} : { description: patch.description }),
          ...(patch.website === undefined ? {} : { website: patch.website }),
          origin: 'curated',
          version: { increment: 1 },
        },
      });
      if (count === 0) throw conflict('The vendor was modified concurrently; retry');
      const updated = await this.require(tx, vendorId);
      await tx.outboxEvent.createMany({
        data: outboxRows([
          assetEvent(
            ASSET_EVENT_TYPES.vendorUpdated,
            vendorUpdatedPayloadSchema,
            { ...vendorSnapshot(updated), actor: context.actor, changedFields },
            context,
          ),
        ]),
      });
      return updated;
    });
    this.logger.info({ vendorId, changedFields }, 'vendor updated');
    return { vendor: toVendor(row), changed: true };
  }

  /** Deletes a vendor without products. Products must be deleted (or kept) explicitly first. */
  async delete(context: ActorContext, vendorId: string, precondition: Precondition): Promise<void> {
    const current = await this.require(this.prisma, vendorId);
    checkPrecondition(precondition, current.version);
    await this.prisma.$transaction(async (tx) => {
      const products = await tx.product.count({ where: { vendorId } });
      if (products > 0) {
        throw conflict(`The vendor still has ${String(products)} product(s); delete them first`);
      }
      const { count } = await tx.vendor.deleteMany({
        where: { id: vendorId, version: current.version },
      });
      if (count === 0) throw conflict('The vendor was modified concurrently; retry');
      await tx.outboxEvent.createMany({
        data: outboxRows([
          assetEvent(
            ASSET_EVENT_TYPES.vendorDeleted,
            vendorDeletedPayloadSchema,
            { ...vendorSnapshot(current), actor: context.actor },
            context,
          ),
        ]),
      });
    });
    this.logger.info({ vendorId, slug: current.slug }, 'vendor deleted');
  }

  private async require(db: PrismaClient | Tx, vendorId: string): Promise<VendorRow> {
    const row = await db.vendor.findUnique({ where: { id: vendorId } });
    if (!row) throw notFound(`Vendor ${vendorId} not found`);
    return row;
  }
}
