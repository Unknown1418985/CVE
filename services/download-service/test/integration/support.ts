import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { CreateBucketCommand, HeadBucketCommand, S3Client } from '@aws-sdk/client-s3';

import {
  OBJECT_STORAGE_BUCKETS,
  POC_EVENT_TYPES,
  type ArtifactDiscoveredPayload,
  type ArtifactVerificationChangedPayload,
} from '@cve/contracts';
import { createRedisConnection } from '@cve/jobs';
import { createDomainEvent, type DomainEvent } from '@cve/messaging';
import { integrationHost, requireEnv, serviceRedisUrl } from '@cve/testing/integration';

import type { Env } from '../../src/config/env.js';
import type { PrismaClient } from '../../src/persistence/prisma.js';
import { downloadTestEnv, silentLogger } from '../support.js';

const override = (name: string) => {
  const value = process.env[name];
  return value === undefined || value === '' ? undefined : value;
};

/** Database URL of the download-service role (override: `DOWNLOAD_SERVICE_TEST_DATABASE_URL`). */
export function databaseUrl(): string {
  return (
    override('DOWNLOAD_SERVICE_TEST_DATABASE_URL') ??
    `postgresql://download_service:${encodeURIComponent(requireEnv('DOWNLOAD_SERVICE_DB_PASSWORD'))}@${integrationHost()}:5432/download_service`
  );
}

export function redisUrl(): string {
  return override('DOWNLOAD_SERVICE_TEST_REDIS_URL') ?? serviceRedisUrl('download-service');
}

/** MinIO; defaults to the dev stack (buckets provisioned by `minio-init`). */
export function s3Settings() {
  return {
    S3_ENDPOINT: override('DOWNLOAD_SERVICE_TEST_S3_ENDPOINT') ?? `http://${integrationHost()}:9000`,
    S3_ACCESS_KEY_ID: override('DOWNLOAD_SERVICE_TEST_S3_ACCESS_KEY_ID') ?? 'download-service',
    S3_SECRET_ACCESS_KEY:
      override('DOWNLOAD_SERVICE_TEST_S3_SECRET_ACCESS_KEY') ?? requireEnv('DOWNLOAD_SERVICE_MINIO_SECRET_KEY'),
  };
}

/** clamd (`host:port`) and the YARA command-line scanner; both are required by this suite. */
export function scannerSettings() {
  const [host = integrationHost(), port = '3310'] = (override('DOWNLOAD_SERVICE_TEST_CLAMAV') ?? '').split(':').filter(Boolean);
  return {
    CLAMAV_HOST: host,
    CLAMAV_PORT: port,
    YARA_BINARY: override('DOWNLOAD_SERVICE_TEST_YARA_BINARY') ?? '/usr/bin/yara',
    YARA_RULES_PATH: resolve(import.meta.dirname, '../../yara/index.yar'),
  };
}

export function integrationEnv(sources: { githubOrigin: string; exploitDbOrigin: string }): Env {
  return downloadTestEnv({
    DATABASE_URL: databaseUrl(),
    REDIS_URL: redisUrl(),
    ...s3Settings(),
    ...scannerSettings(),
    DOWNLOAD_SOURCES_ENABLED: 'github-archive,exploit-db',
    DOWNLOAD_AUTOMATIC_SOURCES: 'github-archive,exploit-db',
    DOWNLOAD_GITHUB_ARCHIVE_URL: sources.githubOrigin,
    DOWNLOAD_EXPLOIT_DB_URL: sources.exploitDbOrigin,
    DOWNLOAD_EXPLOIT_DB_EXTRA_HOSTS: 'none',
    DOWNLOAD_MAX_BYTES: String(256 * 1024),
    DOWNLOAD_RETRY_BACKOFF_MS: '1000',
    DOWNLOAD_JOB_ATTEMPTS: '3',
    SCAN_JOB_ATTEMPTS: '2',
    DOWNLOAD_TOTAL_TIMEOUT_MS: '10000',
    DOWNLOAD_STAGING_DIR: mkdtempSync(join(tmpdir(), 'download-staging-')),
  });
}

export function migrate(url: string): void {
  execFileSync('pnpm', ['exec', 'prisma', 'migrate', 'deploy'], {
    cwd: resolve(import.meta.dirname, '../..'),
    env: { ...process.env, DATABASE_URL: url },
    stdio: 'pipe',
  });
}

/**
 * Empties the service tables. Refuses to run against a database holding data this suite did not
 * create: every source URL must point to a synthetic `*.test` host.
 */
export async function resetDatabase(prisma: PrismaClient): Promise<void> {
  const [foreign] = await prisma.$queryRaw<{ count: bigint }[]>`
    SELECT count(*) AS "count" FROM "download_requests"
     WHERE "source_url" !~ '^https://[a-z0-9.-]+\\.test(:[0-9]+)?/'`;
  if (foreign === undefined || foreign.count > 0n) {
    throw new Error(
      'The download_service database contains data this suite did not create; use a disposable database.',
    );
  }
  await prisma.$executeRaw`
    TRUNCATE "artifact_lifecycle_events", "scan_results", "artifact_sources", "download_attempts",
             "download_requests", "stored_artifacts", "poc_artifact_states", "processed_events",
             "outbox_events"`;
}

/** Creates the buckets when the credentials allow it (sandbox MinIO); the dev stack has them. */
export async function ensureBuckets(env: Env): Promise<void> {
  const client = new S3Client({
    endpoint: env.S3_ENDPOINT,
    region: env.S3_REGION,
    forcePathStyle: true,
    credentials: { accessKeyId: env.S3_ACCESS_KEY_ID, secretAccessKey: env.S3_SECRET_ACCESS_KEY },
  });
  try {
    for (const bucket of [OBJECT_STORAGE_BUCKETS.pocQuarantine, OBJECT_STORAGE_BUCKETS.pocArtifacts]) {
      try {
        await client.send(new HeadBucketCommand({ Bucket: bucket }));
      } catch {
        await client.send(new CreateBucketCommand({ Bucket: bucket }));
      }
    }
  } finally {
    client.destroy();
  }
}

export function redisConnection(env: Env): ReturnType<typeof createRedisConnection> {
  return createRedisConnection({
    url: env.REDIS_URL,
    connectionName: 'download-service:test',
    logger: silentLogger,
    role: 'worker',
  });
}

/** Synthetic identifiers only: owners `zz-test…`, CVE IDs `CVE-2026-9xxxxx`. */
export const syntheticCveId = (n: number) => `CVE-2026-${String(900_000 + n)}`;
export const hexSha = (seed: number) => seed.toString(16).padStart(40, '0');

export function artifactDiscovered(input: {
  artifactId: string;
  repositoryId: string;
  fullName: string;
  commitSha: string;
  cveIds: string[];
  totalBytes?: number;
}): DomainEvent<ArtifactDiscoveredPayload> {
  return createDomainEvent({
    eventType: POC_EVENT_TYPES.artifactDiscovered,
    producer: 'poc-service',
    payload: {
      artifactId: input.artifactId,
      repositoryId: input.repositoryId,
      repositoryUrl: `https://github.com/${input.fullName}`,
      repositoryFullName: input.fullName,
      commitSha: input.commitSha,
      treeSha: input.commitSha,
      fingerprint: 'c'.repeat(64),
      fileCount: 2,
      totalBytes: input.totalBytes ?? 1_000,
      riskIndicators: [],
      duplicate: null,
      cveIds: input.cveIds,
      verificationStatus: 'unverified',
    },
  });
}

export function verificationChanged(
  input: Omit<ArtifactVerificationChangedPayload, 'actor' | 'reason'> & { reason?: string },
): DomainEvent<ArtifactVerificationChangedPayload> {
  return createDomainEvent({
    eventType: POC_EVENT_TYPES.artifactVerificationChanged,
    producer: 'poc-service',
    payload: {
      ...input,
      reason: input.reason ?? 'analyst decision',
      actor: { type: 'user', id: 'analyst-1', username: 'zz-test-analyst' },
    },
  });
}

/** Polls until `check` returns a value (jobs run asynchronously in BullMQ workers). */
export async function waitFor<T>(
  check: () => Promise<T | null | undefined | false>,
  timeoutMs = 30_000,
  label = 'condition',
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await check();
    if (value !== null && value !== undefined && value !== false) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}
