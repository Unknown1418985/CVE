import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

import { integrationHost, requireEnv, serviceRedisUrl } from '@cve/testing/integration';

import type { PrismaClient } from '../../src/persistence/prisma.js';

/** Runs and records created by this suite carry this `requested_by`. */
export const TEST_REQUESTER = 'integration-test';

/**
 * Database URL of the intelligence-service role on the dev-published PostgreSQL. Override with
 * `INTELLIGENCE_SERVICE_TEST_DATABASE_URL` to use another server.
 */
export function intelligenceDatabaseUrl(): string {
  const override = process.env['INTELLIGENCE_SERVICE_TEST_DATABASE_URL'];
  if (override !== undefined && override !== '') return override;
  const password = encodeURIComponent(requireEnv('INTELLIGENCE_SERVICE_DB_PASSWORD'));
  return `postgresql://intelligence_service:${password}@${integrationHost()}:5432/intelligence_service`;
}

/** Redis URL of the intelligence-service ACL user (override: `INTELLIGENCE_SERVICE_TEST_REDIS_URL`). */
export function intelligenceRedisUrl(): string {
  const override = process.env['INTELLIGENCE_SERVICE_TEST_REDIS_URL'];
  return override !== undefined && override !== ''
    ? override
    : serviceRedisUrl('intelligence-service');
}

/** Applies the committed migrations exactly as the `intelligence-service-migrate` job does. */
export function migrate(databaseUrl: string): void {
  execFileSync('pnpm', ['exec', 'prisma', 'migrate', 'deploy'], {
    cwd: resolve(import.meta.dirname, '../..'),
    env: { ...process.env, DATABASE_URL: databaseUrl },
    stdio: 'pipe',
  });
}

/**
 * Empties the service tables between tests. Refuses to run against a database that holds
 * anything this suite did not create (real synchronisation history or non-synthetic records).
 */
export async function resetDatabase(prisma: PrismaClient): Promise<void> {
  const [foreign] = await prisma.$queryRaw<{ runs: bigint; records: bigint }[]>`
    SELECT (SELECT count(*) FROM "sync_runs" WHERE "requested_by" IS DISTINCT FROM ${TEST_REQUESTER}) AS "runs",
           (SELECT count(*) FROM "source_records"
             WHERE "cve_id" IS NOT NULL AND "cve_id" !~ '^CVE-2026-9[0-9]{4}$') AS "records"`;
  if (foreign === undefined || foreign.runs > 0n || foreign.records > 0n) {
    throw new Error(
      'The intelligence_service database contains data this suite did not create; run the integration tests against a disposable database.',
    );
  }
  await prisma.$executeRaw`TRUNCATE "sync_run_issues", "source_record_revisions", "source_records", "sync_runs", "source_sync_states", "epss_scores", "outbox_events"`;
}
