import { Inject, Injectable } from '@nestjs/common';

import { RECORD_SEVERITIES, type SeverityCounts, type VendorAnalytics } from '@cve/contracts';

import { toVendorRef } from '../catalog/mapping.js';
import { notFound } from '../common/http.js';
import type { PrismaClient } from '../generated/prisma/client.js';
import { Prisma, PRISMA } from '../persistence/database.js';

/**
 * Active `affected` associations of one vendor, joined with the mirrored CVE facts. A CVE that
 * affects several products or is reported by several sources counts once per CVE (`c`) or once
 * per product (`p`).
 */
const vendorCves = (vendorId: string) => Prisma.sql`
  c AS (
    SELECT DISTINCT a."cve_id" FROM "cve_product_associations" AS a
     WHERE a."vendor_id" = ${vendorId}::uuid AND a."withdrawn_at" IS NULL AND a."status" = 'affected'
  ),
  cf AS (
    SELECT c."cve_id", f."id" AS "fact_id", coalesce(f."severity"::text, 'unknown') AS "severity",
           f."cvss_score", f."epss_score", coalesce(f."in_kev", false) AS "in_kev"
      FROM c LEFT JOIN "cve_facts" AS f ON f."cve_id" = c."cve_id" AND f."deleted_at" IS NULL
  )`;

interface Totals {
  cveCount: number;
  withoutFacts: number;
  kevCount: number;
  averageCvss: number | null;
  maxCvss: number | null;
  maxEpss: number | null;
}

/** Vendor vulnerability analytics, computed on request in the Asset Service database. */
@Injectable()
export class VendorAnalyticsService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClient) {}

  async forVendor(vendorId: string, topProducts: number): Promise<VendorAnalytics> {
    const vendor = await this.prisma.vendor.findUnique({ where: { id: vendorId } });
    if (!vendor) throw notFound(`Vendor ${vendorId} not found`);

    // One snapshot for every figure: REPEATABLE READ makes the queries see the same data.
    return this.prisma.$transaction(
      async (tx) => {
        const [totals] = await tx.$queryRaw<Totals[]>`
          WITH ${vendorCves(vendorId)}
          SELECT count(*)::int AS "cveCount",
                 count(*) FILTER (WHERE "fact_id" IS NULL)::int AS "withoutFacts",
                 count(*) FILTER (WHERE "in_kev")::int AS "kevCount",
                 round(avg("cvss_score"), 2)::float8 AS "averageCvss",
                 max("cvss_score")::float8 AS "maxCvss",
                 max("epss_score")::float8 AS "maxEpss"
            FROM cf`;
        const severities = await tx.$queryRaw<{ severity: string; count: number }[]>`
          WITH ${vendorCves(vendorId)}
          SELECT "severity", count(*)::int AS "count" FROM cf GROUP BY "severity"`;
        const years = await tx.$queryRaw<{ year: number; cveCount: number }[]>`
          WITH ${vendorCves(vendorId)}
          SELECT split_part("cve_id", '-', 2)::int AS "year", count(*)::int AS "cveCount"
            FROM c GROUP BY 1 ORDER BY 1`;
        const sources = await tx.$queryRaw<{ source: string; cveCount: number }[]>`
          SELECT a."source", count(DISTINCT a."cve_id")::int AS "cveCount"
            FROM "cve_product_associations" AS a
           WHERE a."vendor_id" = ${vendorId}::uuid AND a."withdrawn_at" IS NULL
             AND a."status" = 'affected'
           GROUP BY a."source" ORDER BY 2 DESC, 1`;
        const products = await tx.$queryRaw<
          {
            id: string;
            slug: string;
            name: string;
            cveCount: number;
            criticalCount: number;
            highCount: number;
            kevCount: number;
          }[]
        >`
          WITH p AS (
            SELECT DISTINCT a."product_id", a."cve_id" FROM "cve_product_associations" AS a
             WHERE a."vendor_id" = ${vendorId}::uuid AND a."withdrawn_at" IS NULL
               AND a."status" = 'affected'
          )
          SELECT pr."id", pr."slug", pr."name", count(*)::int AS "cveCount",
                 count(*) FILTER (WHERE f."severity" = 'critical')::int AS "criticalCount",
                 count(*) FILTER (WHERE f."severity" = 'high')::int AS "highCount",
                 count(*) FILTER (WHERE f."in_kev")::int AS "kevCount"
            FROM p
            JOIN "products" AS pr ON pr."id" = p."product_id"
            LEFT JOIN "cve_facts" AS f ON f."cve_id" = p."cve_id" AND f."deleted_at" IS NULL
           GROUP BY pr."id", pr."slug", pr."name"
           ORDER BY 4 DESC, 5 DESC, pr."name", pr."id"
           LIMIT ${topProducts}`;
        const [span] = await tx.$queryRaw<
          { products: number; affected: number; first: Date | null; last: Date | null }[]
        >`
          SELECT (SELECT count(*)::int FROM "products" WHERE "vendor_id" = ${vendorId}::uuid) AS "products",
                 count(DISTINCT a."product_id") FILTER (
                   WHERE a."withdrawn_at" IS NULL AND a."status" = 'affected')::int AS "affected",
                 min(a."first_seen_at") AS "first", max(a."first_seen_at") AS "last"
            FROM "cve_product_associations" AS a
           WHERE a."vendor_id" = ${vendorId}::uuid`;

        const bySeverity = Object.fromEntries(
          RECORD_SEVERITIES.map((severity) => [severity, 0]),
        ) as SeverityCounts;
        for (const row of severities) {
          if ((RECORD_SEVERITIES as readonly string[]).includes(row.severity)) {
            bySeverity[row.severity as keyof SeverityCounts] = row.count;
          }
        }
        return {
          vendor: toVendorRef(vendor),
          productCount: span?.products ?? 0,
          affectedProductCount: span?.affected ?? 0,
          cveCount: totals?.cveCount ?? 0,
          cvesWithoutFacts: totals?.withoutFacts ?? 0,
          bySeverity,
          kevCount: totals?.kevCount ?? 0,
          averageCvssScore: totals?.averageCvss ?? null,
          maxCvssScore: totals?.maxCvss ?? null,
          maxEpssScore: totals?.maxEpss ?? null,
          byCveYear: years,
          bySource: sources,
          topProducts: products,
          firstAssociatedAt: span?.first?.toISOString() ?? null,
          lastAssociatedAt: span?.last?.toISOString() ?? null,
          generatedAt: new Date().toISOString(),
        };
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead },
    );
  }
}
