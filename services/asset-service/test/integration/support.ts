import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';

import {
  CVE_EVENT_TYPES,
  cveObservationRecordedPayloadSchema,
  INTELLIGENCE_EVENT_TYPES,
  type CveObservationRecordedPayload,
  type CveRecordCreatedPayload,
  type CveRecordDeletedPayload,
} from '@cve/contracts';
import type { DomainEvent } from '@cve/messaging';
import { integrationHost, requireEnv } from '@cve/testing/integration';

import type { CveRecordEvent } from '../../src/events/cve-facts.projector.js';
import type { PrismaClient } from '../../src/persistence/prisma.js';

/**
 * Database URL of the asset-service role on the dev-published PostgreSQL. Override with
 * `ASSET_SERVICE_TEST_DATABASE_URL` to use another server.
 */
export function assetDatabaseUrl(): string {
  const override = process.env['ASSET_SERVICE_TEST_DATABASE_URL'];
  if (override !== undefined && override !== '') return override;
  const password = encodeURIComponent(requireEnv('ASSET_SERVICE_DB_PASSWORD'));
  return `postgresql://asset_service:${password}@${integrationHost()}:5432/asset_service`;
}

/** Applies the committed migrations exactly as the `asset-service-migrate` job does. */
export function migrate(databaseUrl: string): void {
  execFileSync('pnpm', ['exec', 'prisma', 'migrate', 'deploy'], {
    cwd: resolve(import.meta.dirname, '../..'),
    env: { ...process.env, DATABASE_URL: databaseUrl },
    stdio: 'pipe',
  });
}

/**
 * Synthetic test data only: vendor slugs start with `zz_test`, CVE IDs are `CVE-2026-9xxxxx`.
 * `removeSyntheticData` deletes exactly that data before each test.
 */
export const syntheticCveId = (n: number) => `CVE-2026-${String(900_000 + n)}`;
export const SYNTHETIC_VENDOR_PREFIX = 'zz_test';
const PREFIX_PATTERN = 'zz\\_test%';

export async function removeSyntheticData(prisma: PrismaClient): Promise<void> {
  const cves = '^CVE-2026-9[0-9]{5}$';
  await prisma.$executeRaw`DELETE FROM "cve_product_associations" WHERE "cve_id" ~ ${cves}`;
  await prisma.$executeRaw`
    DELETE FROM "products" WHERE "vendor_id" IN (SELECT "id" FROM "vendors" WHERE "slug" LIKE ${PREFIX_PATTERN})`;
  await prisma.$executeRaw`DELETE FROM "products" WHERE "slug" LIKE ${PREFIX_PATTERN}`;
  await prisma.$executeRaw`DELETE FROM "vendors" WHERE "slug" LIKE ${PREFIX_PATTERN}`;
  // Ecosystem vendors (GitHub advisories) created only by these tests and left without products.
  await prisma.$executeRaw`
    DELETE FROM "vendors" WHERE "slug" = 'npm' AND "origin" = 'discovered' AND "source" = 'github-advisory'
       AND NOT EXISTS (SELECT 1 FROM "products" AS p WHERE p."vendor_id" = "vendors"."id")`;
  await prisma.$executeRaw`DELETE FROM "cve_facts" WHERE "cve_id" ~ ${cves}`;
  await prisma.$executeRaw`DELETE FROM "observation_cursors" WHERE "cve_id" ~ ${cves}`;
  await prisma.$executeRaw`
    DELETE FROM "outbox_events" WHERE "envelope"::text ~ 'zz_test|CVE-2026-9[0-9]{5}'`;
  await prisma.$executeRaw`
    DELETE FROM "outbox_events" WHERE "event_type" = 'asset.vendor.created'
       AND "envelope" -> 'payload' ->> 'slug' = 'npm'
       AND NOT EXISTS (SELECT 1 FROM "vendors" WHERE "slug" = 'npm')`;
}

const SHA = 'a'.repeat(64);

/** A synthetic `intelligence.cve-observation.recorded` event. */
export function observationEvent(input: {
  cveId: string;
  source?: 'nvd' | 'mitre-cve' | 'github-advisory';
  sourceRecordId?: string;
  revision: number;
  products: readonly Record<string, unknown>[];
  observedAt?: string;
}): DomainEvent<CveObservationRecordedPayload> {
  const source = input.source ?? 'nvd';
  const payload = cveObservationRecordedPayloadSchema.parse({
    source,
    sourceRecordId: input.sourceRecordId ?? input.cveId,
    sourceUrl: `https://example.com/synthetic/${input.cveId}`,
    attribution: 'Synthetic integration test data',
    revision: input.revision,
    contentHash: SHA,
    observedAt: input.observedAt ?? new Date().toISOString(),
    sourceModifiedAt: null,
    runId: randomUUID(),
    cveId: input.cveId,
    change: input.revision === 1 ? 'created' : 'updated',
    content: {
      description: `Synthetic integration test record ${input.cveId}. Not a real vulnerability.`,
      source,
      affectedProducts: input.products.map((product) => ({ source, ...product })),
    },
    truncated: [],
  });
  return {
    eventId: randomUUID(),
    eventType: INTELLIGENCE_EVENT_TYPES.cveObserved,
    eventVersion: 1,
    occurredAt: new Date().toISOString(),
    producer: 'intelligence-service',
    correlationId: 'integration-test',
    payload,
  };
}

const actor = { type: 'service' as const, id: 'integration-test', username: null };

/** A synthetic `cve.record.created` (or `updated`) event. */
export function cveRecordEvent(
  cveId: string,
  facts: Partial<CveRecordCreatedPayload> & { version: number; recordId: string },
  occurredAt = new Date(),
): CveRecordEvent {
  const payload: CveRecordCreatedPayload = {
    cveId,
    state: 'published',
    severity: 'unknown',
    cvssScore: null,
    cvssVersion: null,
    inKev: false,
    epssScore: null,
    epssPercentile: null,
    cweIds: [],
    publishedAt: '2026-01-01T00:00:00.000Z',
    lastModifiedAt: null,
    actor,
    ...facts,
  };
  return {
    eventId: randomUUID(),
    eventType: facts.version === 1 ? CVE_EVENT_TYPES.created : CVE_EVENT_TYPES.updated,
    eventVersion: 1,
    occurredAt: occurredAt.toISOString(),
    producer: 'cve-service',
    payload,
  };
}

export function cveDeletedEvent(cveId: string, recordId: string, version: number): CveRecordEvent {
  const payload: CveRecordDeletedPayload = { cveId, recordId, version, actor };
  return {
    eventId: randomUUID(),
    eventType: CVE_EVENT_TYPES.deleted,
    eventVersion: 1,
    occurredAt: new Date().toISOString(),
    producer: 'cve-service',
    payload,
  };
}
