import type { DomainEventEnvelope } from '@cve/contracts';

import { Prisma } from '../generated/prisma/client.js';

export { Prisma } from '../generated/prisma/client.js';

/** Nest injection token of the service's PrismaClient. */
export const PRISMA = Symbol('PRISMA');

export type Tx = Prisma.TransactionClient;

/**
 * Interactive transaction limits. Applying one observation can resolve up to 2,000 affected
 * products, so the timeout is longer than Prisma's 5 s default.
 */
export const TX_OPTIONS = { maxWait: 10_000, timeout: 60_000 } as const;

export function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

/** Escapes LIKE wildcards (PostgreSQL's default escape character is the backslash). */
export function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, (char) => `\\${char}`);
}

export function outboxRows(
  events: readonly DomainEventEnvelope[],
): Prisma.OutboxEventCreateManyInput[] {
  return events.map((event) => ({
    eventId: event.eventId,
    eventType: event.eventType,
    envelope: JSON.parse(JSON.stringify(event)) as Prisma.InputJsonValue,
  }));
}

export function decimalToNumber(value: Prisma.Decimal | null): number | null {
  return value === null ? null : value.toNumber();
}

/** Recomputes the denormalised CVE counters of products (active `affected` associations). */
export async function refreshProductCounters(tx: Tx, productIds: readonly string[]): Promise<void> {
  if (productIds.length === 0) return;
  await tx.$executeRaw`
    UPDATE "products" AS p
       SET "cve_count" = (
             SELECT count(DISTINCT a."cve_id")::int FROM "cve_product_associations" AS a
              WHERE a."product_id" = p."id" AND a."withdrawn_at" IS NULL AND a."status" = 'affected')
     WHERE p."id" = ANY(${[...productIds]}::uuid[])`;
}

/** Recomputes the denormalised product and CVE counters of vendors. */
export async function refreshVendorCounters(tx: Tx, vendorIds: readonly string[]): Promise<void> {
  if (vendorIds.length === 0) return;
  await tx.$executeRaw`
    UPDATE "vendors" AS v
       SET "product_count" = (SELECT count(*)::int FROM "products" AS p WHERE p."vendor_id" = v."id"),
           "cve_count" = (
             SELECT count(DISTINCT a."cve_id")::int FROM "cve_product_associations" AS a
              WHERE a."vendor_id" = v."id" AND a."withdrawn_at" IS NULL AND a."status" = 'affected')
     WHERE v."id" = ANY(${[...vendorIds]}::uuid[])`;
}
