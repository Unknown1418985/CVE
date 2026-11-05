import { Inject, Injectable } from '@nestjs/common';

import {
  parseCpe23,
  rangeContains,
  versionRangeSchema,
  type AffectedStatus,
  type AssociationSortField,
  type CveFacts,
  type CveProductAssociation,
  type ListCveAssociationsQuery,
  type ListProductVulnerabilitiesQuery,
  type ProductHistoryEntry,
  type ProductHistoryQuery,
  type SetManualAssociationRequest,
} from '@cve/contracts';
import type { Logger } from '@cve/logger';
import { z } from 'zod';

import {
  fromDbHistoryChange,
  fromDbProductType,
  toDbHistoryChange,
  toVendorRef,
} from '../catalog/mapping.js';
import { notFound } from '../common/http.js';
import { APP_LOGGER } from '../common/lifecycle.js';
import type { ActorContext } from '../common/request-context.js';
import type { PrismaClient } from '../generated/prisma/client.js';
import {
  decimalToNumber,
  outboxRows,
  Prisma,
  PRISMA,
  TX_OPTIONS,
} from '../persistence/database.js';
import { applyAssociationSet, canonicalRanges } from './association-writer.js';

/** Provenance of associations maintained by analysts through the API. */
export const MANUAL_SOURCE = 'manual';

/** Upper bound of associations evaluated in memory for a `?version=` filter. */
export const MAX_VERSION_FILTER_CANDIDATES = 20_000;

interface AssociationFilter {
  readonly productId?: string | undefined;
  readonly vendorId?: string | undefined;
  readonly cveId?: string | undefined;
  readonly source?: string | undefined;
  readonly status?: AffectedStatus | undefined;
  readonly severity?: readonly string[] | undefined;
  readonly kev?: boolean | undefined;
  readonly includeWithdrawn: boolean;
  readonly sort: AssociationSortField;
  readonly order: 'asc' | 'desc';
}

const associationInclude = {
  ranges: { orderBy: { rangeKey: 'asc' } },
  product: {
    select: {
      id: true,
      slug: true,
      name: true,
      type: true,
      vendor: { select: { id: true, slug: true, name: true } },
    },
  },
} satisfies Prisma.CveProductAssociationInclude;
type AssociationRow = Prisma.CveProductAssociationGetPayload<{
  include: typeof associationInclude;
}>;
type FactRow = Prisma.CveFactGetPayload<object>;

function toFacts(row: FactRow | undefined): CveFacts | null {
  if (!row) return null;
  return {
    state: row.state,
    severity: row.severity,
    cvssScore: decimalToNumber(row.cvssScore),
    inKev: row.inKev,
    epssScore: decimalToNumber(row.epssScore),
    epssPercentile: decimalToNumber(row.epssPercentile),
    publishedAt: row.publishedAt?.toISOString() ?? null,
  };
}

function toAssociation(row: AssociationRow, fact: FactRow | undefined): CveProductAssociation {
  return {
    id: row.id,
    cveId: row.cveId,
    product: {
      id: row.product.id,
      slug: row.product.slug,
      name: row.product.name,
      type: fromDbProductType(row.product.type),
    },
    vendor: toVendorRef(row.product.vendor),
    source: row.source,
    sourceRecordId: row.sourceRecordId,
    sourceUrl: row.sourceUrl,
    attribution: row.attribution,
    origin: row.origin,
    status: row.status,
    ranges: row.ranges.map((range) => ({
      status: range.status,
      cpe: range.cpe,
      version: range.version,
      versionStartIncluding: range.versionStartIncluding,
      versionStartExcluding: range.versionStartExcluding,
      versionEndIncluding: range.versionEndIncluding,
      versionEndExcluding: range.versionEndExcluding,
    })),
    note: row.note,
    firstSeenAt: row.firstSeenAt.toISOString(),
    lastSeenAt: row.lastSeenAt.toISOString(),
    withdrawnAt: row.withdrawnAt?.toISOString() ?? null,
    cve: toFacts(fact),
  };
}

/**
 * Whether a version is affected according to an association's ranges: `true` when an affected
 * range contains it, `null` when some affected range cannot be compared, otherwise `false`.
 * A CPE-only range uses the CPE's version component as the exact version.
 */
export function versionAffected(
  ranges: readonly {
    status: AffectedStatus;
    cpe: string | null;
    version: string | null;
    versionStartIncluding: string | null;
    versionStartExcluding: string | null;
    versionEndIncluding: string | null;
    versionEndExcluding: string | null;
  }[],
  version: string,
): boolean | null {
  let unknown = false;
  for (const range of ranges) {
    if (range.status !== 'affected') continue;
    const bounded =
      range.version !== null ||
      range.versionStartIncluding !== null ||
      range.versionStartExcluding !== null ||
      range.versionEndIncluding !== null ||
      range.versionEndExcluding !== null;
    const cpeVersion = range.cpe === null ? undefined : parseCpe23(range.cpe)?.version;
    const effective =
      !bounded && cpeVersion !== undefined && cpeVersion !== '*' && cpeVersion !== '-'
        ? { version: cpeVersion }
        : range;
    const result = rangeContains(effective, version);
    if (result === true) return true;
    if (result === null) unknown = true;
  }
  return unknown ? null : false;
}

function whereSql(filter: AssociationFilter): Prisma.Sql {
  const conditions: Prisma.Sql[] = [];
  if (filter.productId !== undefined)
    conditions.push(Prisma.sql`a."product_id" = ${filter.productId}::uuid`);
  if (filter.vendorId !== undefined)
    conditions.push(Prisma.sql`a."vendor_id" = ${filter.vendorId}::uuid`);
  if (filter.cveId !== undefined) conditions.push(Prisma.sql`a."cve_id" = ${filter.cveId}`);
  if (filter.source !== undefined) conditions.push(Prisma.sql`a."source" = ${filter.source}`);
  if (filter.status !== undefined) {
    conditions.push(Prisma.sql`a."status" = ${filter.status}::"affected_status"`);
  }
  if (!filter.includeWithdrawn) conditions.push(Prisma.sql`a."withdrawn_at" IS NULL`);
  if (filter.severity !== undefined) {
    conditions.push(
      Prisma.sql`coalesce(f."severity"::text, 'unknown') = ANY(${[...filter.severity]}::text[])`,
    );
  }
  if (filter.kev !== undefined) {
    conditions.push(Prisma.sql`coalesce(f."in_kev", false) = ${filter.kev}`);
  }
  return conditions.length === 0
    ? Prisma.empty
    : Prisma.sql`WHERE ${Prisma.join(conditions, ' AND ')}`;
}

function orderSql(sort: AssociationSortField, order: 'asc' | 'desc'): Prisma.Sql {
  const direction = Prisma.raw(order === 'asc' ? 'ASC' : 'DESC');
  switch (sort) {
    case 'cveId':
      return Prisma.sql`split_part(a."cve_id", '-', 2)::int ${direction},
                        split_part(a."cve_id", '-', 3)::bigint ${direction}, a."id" ${direction}`;
    case 'cvssScore':
      return Prisma.sql`f."cvss_score" ${direction} NULLS LAST, a."cve_id" ${direction}, a."id"`;
    case 'epssScore':
      return Prisma.sql`f."epss_score" ${direction} NULLS LAST, a."cve_id" ${direction}, a."id"`;
    case 'firstSeenAt':
      return Prisma.sql`a."first_seen_at" ${direction}, a."id" ${direction}`;
    case 'lastSeenAt':
      return Prisma.sql`a."last_seen_at" ${direction}, a."id" ${direction}`;
  }
}

const FROM = Prisma.sql`FROM "cve_product_associations" AS a
  LEFT JOIN "cve_facts" AS f ON f."cve_id" = a."cve_id" AND f."deleted_at" IS NULL`;

const historyRangesSchema = z.array(versionRangeSchema);

/** Reads and analyst writes of CVE-to-product associations. */
@Injectable()
export class AssociationsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClient,
    @Inject(APP_LOGGER) private readonly logger: Logger,
  ) {}

  async listForProduct(
    productId: string,
    query: ListProductVulnerabilitiesQuery,
  ): Promise<{ items: CveProductAssociation[]; total: number }> {
    await this.requireProduct(productId);
    const filter: AssociationFilter = { ...query, productId };
    const version = query.version;
    if (version === undefined) return this.search(filter, query);

    // Version matching is evaluated in memory: version schemes do not order as text in SQL.
    const candidates = await this.prisma.$queryRaw<{ id: string }[]>`
      SELECT a."id" ${FROM} ${whereSql(filter)} ORDER BY ${orderSql(filter.sort, filter.order)}
       LIMIT ${MAX_VERSION_FILTER_CANDIDATES}`;
    const ranges = await this.prisma.affectedVersionRange.findMany({
      where: { associationId: { in: candidates.map((row) => row.id) } },
    });
    const byAssociation = new Map<string, typeof ranges>();
    for (const range of ranges) {
      byAssociation.set(range.associationId, [
        ...(byAssociation.get(range.associationId) ?? []),
        range,
      ]);
    }
    const verdicts = new Map<string, boolean | null>();
    const matching = candidates.filter(({ id }) => {
      const verdict = versionAffected(byAssociation.get(id) ?? [], version);
      verdicts.set(id, verdict);
      return verdict !== false;
    });
    const start = (query.page - 1) * query.pageSize;
    const page = await this.load(
      matching.slice(start, start + query.pageSize).map((row) => row.id),
    );
    return {
      items: page.map((item) => ({ ...item, versionAffected: verdicts.get(item.id) ?? null })),
      total: matching.length,
    };
  }

  search(
    filter: AssociationFilter,
    page: { page: number; pageSize: number },
  ): Promise<{ items: CveProductAssociation[]; total: number }> {
    return this.prisma.$transaction(async (tx) => {
      const where = whereSql(filter);
      const ids = await tx.$queryRaw<{ id: string }[]>`
        SELECT a."id" ${FROM} ${where} ORDER BY ${orderSql(filter.sort, filter.order)}
         LIMIT ${page.pageSize} OFFSET ${(page.page - 1) * page.pageSize}`;
      const [count] = await tx.$queryRaw<{ total: number }[]>`
        SELECT count(*)::int AS "total" ${FROM} ${where}`;
      return {
        items: await this.load(
          ids.map((row) => row.id),
          tx,
        ),
        total: count?.total ?? 0,
      };
    });
  }

  searchAll(query: ListCveAssociationsQuery) {
    return this.search(query, query);
  }

  async history(
    productId: string,
    query: ProductHistoryQuery,
  ): Promise<{ items: ProductHistoryEntry[]; total: number }> {
    await this.requireProduct(productId);
    const where: Prisma.ProductVulnerabilityHistoryWhereInput = {
      productId,
      ...(query.cveId === undefined ? {} : { cveId: query.cveId }),
      ...(query.change === undefined ? {} : { change: toDbHistoryChange(query.change) }),
    };
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.productVulnerabilityHistory.findMany({
        where,
        orderBy: [{ occurredAt: query.order }, { id: query.order }],
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.productVulnerabilityHistory.count({ where }),
    ]);
    return {
      total,
      items: rows.map((row) => ({
        id: row.id,
        productId: row.productId,
        cveId: row.cveId,
        associationId: row.associationId,
        change: fromDbHistoryChange(row.change),
        source: row.source,
        sourceRecordId: row.sourceRecordId,
        ranges: historyRangesSchema.parse(row.ranges),
        occurredAt: row.occurredAt.toISOString(),
      })),
    };
  }

  /** Creates, replaces or restores the analyst-maintained association of a CVE and product. */
  async setManual(
    context: ActorContext,
    productId: string,
    cveId: string,
    input: SetManualAssociationRequest,
  ): Promise<{ association: CveProductAssociation; created: boolean }> {
    await this.requireProduct(productId);
    const result = await this.prisma.$transaction(async (tx) => {
      const { changes, events } = await applyAssociationSet(
        tx,
        {
          source: MANUAL_SOURCE,
          sourceRecordId: cveId,
          origin: 'manual',
          sourceUrl: null,
          attribution: null,
          note: input.note,
          scope: { cveId, productId },
          desired: [{ cveId, productId, ranges: canonicalRanges(input.ranges) }],
          seenAt: new Date(),
        },
        context,
      );
      if (events.length > 0) await tx.outboxEvent.createMany({ data: outboxRows(events) });
      return changes;
    }, TX_OPTIONS);
    const [row] = await this.prisma.cveProductAssociation.findMany({
      where: { productId, cveId, source: MANUAL_SOURCE, sourceRecordId: cveId },
      select: { id: true },
    });
    if (!row) throw new Error('manual association missing after write');
    const [association] = await this.load([row.id]);
    if (!association) throw new Error('manual association missing after write');
    this.logger.info(
      { productId, cveId, changes: result.map((c) => c.change) },
      'manual association set',
    );
    return { association, created: result.some((change) => change.change === 'added') };
  }

  /** Withdraws the analyst-maintained association; associations from sources are not touched. */
  async withdrawManual(context: ActorContext, productId: string, cveId: string): Promise<void> {
    await this.requireProduct(productId);
    const changes = await this.prisma.$transaction(async (tx) => {
      const active = await tx.cveProductAssociation.count({
        where: {
          productId,
          cveId,
          source: MANUAL_SOURCE,
          sourceRecordId: cveId,
          withdrawnAt: null,
        },
      });
      if (active === 0) {
        throw notFound(`No active manual association of ${cveId} with product ${productId}`);
      }
      const result = await applyAssociationSet(
        tx,
        {
          source: MANUAL_SOURCE,
          sourceRecordId: cveId,
          origin: 'manual',
          sourceUrl: null,
          attribution: null,
          scope: { cveId, productId },
          desired: [],
          seenAt: new Date(),
        },
        context,
      );
      await tx.outboxEvent.createMany({ data: outboxRows(result.events) });
      return result.changes;
    }, TX_OPTIONS);
    this.logger.info({ productId, cveId, changes: changes.length }, 'manual association withdrawn');
  }

  private async load(
    ids: readonly string[],
    db: PrismaClient | Prisma.TransactionClient = this.prisma,
  ): Promise<CveProductAssociation[]> {
    if (ids.length === 0) return [];
    const rows = await db.cveProductAssociation.findMany({
      where: { id: { in: [...ids] } },
      include: associationInclude,
    });
    const facts = await db.cveFact.findMany({
      where: { cveId: { in: [...new Set(rows.map((row) => row.cveId))] }, deletedAt: null },
    });
    const factByCve = new Map(facts.map((fact) => [fact.cveId, fact]));
    const byId = new Map(rows.map((row) => [row.id, row]));
    return ids.flatMap((id) => {
      const row = byId.get(id);
      return row ? [toAssociation(row, factByCve.get(row.cveId))] : [];
    });
  }

  private async requireProduct(productId: string): Promise<void> {
    const product = await this.prisma.product.findUnique({
      where: { id: productId },
      select: { id: true },
    });
    if (!product) throw notFound(`Product ${productId} not found`);
  }
}
