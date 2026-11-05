import { isAbsolute, resolve } from 'node:path';

import {
  booleanStringSchema,
  httpUrlSchema,
  loadEnv,
  objectStorageEnvSchema,
  serviceEnvSchema,
  type EnvSource,
} from '@cve/config';
import { ARTIFACT_SCANNERS, DOWNLOAD_SOURCES, SERVICE_DEFAULT_PORTS } from '@cve/contracts';
import { assertServiceOwnsDatabase } from '@cve/database';
import { z } from 'zod';

import { SERVICE_NAME, SERVICE_VERSION } from '../service.js';

const MINUTE_MS = 60_000;
const MIB = 1024 * 1024;

const cronSchema = z
  .string()
  .trim()
  .regex(/^(\S+\s+){4}\S+$/, { message: 'must be a five-field cron expression' });

const int = (min: number, max: number) => z.coerce.number().int().min(min).max(max);

/** Comma-separated subset of an allowed list (`none` or empty means none). */
function subsetSchema<T extends string>(allowed: readonly T[], label: string) {
  return z
    .string()
    .trim()
    .transform((value, ctx): T[] => {
      const names =
        value === '' || value === 'none' ? [] : value.split(',').map((name) => name.trim());
      const unknown = names.filter((name) => !(allowed as readonly string[]).includes(name));
      if (unknown.length > 0) {
        ctx.addIssue({
          code: 'custom',
          message: `not approved ${label}: ${unknown.join(', ')} (approved: ${allowed.join(', ')})`,
        });
        return z.NEVER;
      }
      return [...new Set(names)] as T[];
    });
}

/** Comma-separated host names (lower-case, no ports, no IP literals). */
const hostListSchema = z
  .string()
  .trim()
  .transform((value) =>
    value === '' || value === 'none'
      ? []
      : value.split(',').map((host) => host.trim().toLowerCase()),
  )
  .pipe(
    z.array(
      z
        .string()
        .regex(/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/, {
          message: 'must be a DNS host name',
        }),
    ),
  );

/** Source base URL: https only, no credentials, path or query. */
const sourceBaseUrlSchema = httpUrlSchema.refine(
  (value) => {
    const url = new URL(value);
    return (
      url.protocol === 'https:' &&
      url.username === '' &&
      url.password === '' &&
      (url.pathname === '/' || url.pathname === '') &&
      url.search === ''
    );
  },
  { message: 'must be an https origin without credentials, path or query' },
);

const absolutePath = z
  .string()
  .trim()
  .refine((value) => isAbsolute(value), { message: 'must be an absolute path' });

/** A file path; a relative one is resolved against the working directory (local development). */
const filePath = z
  .string()
  .trim()
  .min(1)
  .transform((value) => resolve(value));

export const envSchema = serviceEnvSchema(SERVICE_DEFAULT_PORTS[SERVICE_NAME])
  .extend(objectStorageEnvSchema.shape)
  .extend({
    KEYCLOAK_URL: httpUrlSchema,
    KEYCLOAK_PUBLIC_URL: httpUrlSchema,
    KEYCLOAK_REALM: z
      .string()
      .regex(/^[A-Za-z0-9_-]{1,64}$/)
      .default('cve-platform'),
    KEYCLOAK_AUDIENCE: z.string().min(1).default('cve-api'),
    KEYCLOAK_TIMEOUT_MS: int(500, 30_000).default(5_000),
    /** Publishes outbox events to RabbitMQ. Disabled only in tests. */
    OUTBOX_RELAY_ENABLED: booleanStringSchema.default(true),
    /** Consumes `poc.artifact.*` and `poc.reference.discovered`. Disabled only in tests. */
    EVENT_CONSUMERS_ENABLED: booleanStringSchema.default(true),
    /** Runs the BullMQ download and scan workers and schedules. Disabled only in tests. */
    DOWNLOAD_WORKER_ENABLED: booleanStringSchema.default(true),

    // ---- sources
    /** Approved sources enabled on this deployment (comma-separated, or `none`). */
    DOWNLOAD_SOURCES_ENABLED: subsetSchema(DOWNLOAD_SOURCES, 'download sources').default([
      'github-archive',
    ]),
    /** Sources downloaded automatically from PoC Service events (a subset of the enabled ones). */
    DOWNLOAD_AUTOMATIC_SOURCES: subsetSchema(DOWNLOAD_SOURCES, 'download sources').default([
      'github-archive',
    ]),
    DOWNLOAD_GITHUB_ARCHIVE_URL: sourceBaseUrlSchema.default('https://codeload.github.com'),
    /** Extra hosts GitHub archive downloads may be redirected to (the base URL's host is always allowed). */
    DOWNLOAD_GITHUB_ARCHIVE_EXTRA_HOSTS: hostListSchema.default([]),
    DOWNLOAD_EXPLOIT_DB_URL: sourceBaseUrlSchema.default('https://www.exploit-db.com'),
    DOWNLOAD_EXPLOIT_DB_EXTRA_HOSTS: hostListSchema.default(['exploit-db.com']),

    // ---- limits
    /** Largest artifact accepted (declared and streamed bytes). */
    DOWNLOAD_MAX_BYTES: int(1_024, 2_048 * MIB).default(100 * MIB),
    /** Skip PoC artifacts whose uncompressed listing is larger than this many times the limit. */
    DOWNLOAD_MAX_EXPECTED_RATIO: int(1, 100).default(4),
    DOWNLOAD_RESPONSE_TIMEOUT_MS: int(1_000, 120_000).default(15_000),
    DOWNLOAD_IDLE_TIMEOUT_MS: int(1_000, 300_000).default(30_000),
    DOWNLOAD_TOTAL_TIMEOUT_MS: int(5_000, 60 * MINUTE_MS).default(10 * MINUTE_MS),
    DOWNLOAD_MAX_REDIRECTS: int(0, 10).default(5),
    DOWNLOAD_USER_AGENT: z
      .string()
      .trim()
      .min(1)
      .max(200)
      .default(`cve-intelligence-platform/${SERVICE_VERSION} (self-hosted; artifact download)`),
    /** Private directory for files while they are hashed, scanned and uploaded. */
    DOWNLOAD_STAGING_DIR: absolutePath.default('/tmp/download-staging'),

    // ---- jobs
    DOWNLOAD_JOB_ATTEMPTS: int(1, 20).default(4),
    DOWNLOAD_RETRY_BACKOFF_MS: int(1_000, 6 * 60 * MINUTE_MS).default(MINUTE_MS),
    DOWNLOAD_CONCURRENCY: int(1, 16).default(2),
    /** Downloads started per minute across all replicas (BullMQ limiter). */
    DOWNLOAD_RATE_LIMIT_PER_MINUTE: int(1, 600).default(30),
    SCAN_CONCURRENCY: int(1, 8).default(1),
    SCAN_JOB_ATTEMPTS: int(1, 20).default(5),
    DOWNLOAD_SCHEDULER_CRON: cronSchema.default('* * * * *'),
    DOWNLOAD_SCHEDULER_BATCH_SIZE: int(1, 1_000).default(50),
    DOWNLOAD_MAINTENANCE_CRON: cronSchema.default('17 * * * *'),
    PROCESSED_EVENT_RETENTION_DAYS: int(1, 365).default(30),
    OUTBOX_RETENTION_DAYS: int(1, 365).default(7),

    // ---- scanners
    /** Scanners that must report clean before an artifact can be released. */
    SCAN_REQUIRED_SCANNERS: subsetSchema(ARTIFACT_SCANNERS, 'scanners').default(['clamav', 'yara']),
    CLAMAV_ENABLED: booleanStringSchema.default(true),
    CLAMAV_HOST: z.string().trim().min(1).max(253).default('clamav'),
    CLAMAV_PORT: int(1, 65_535).default(3310),
    CLAMAV_TIMEOUT_MS: int(1_000, 30 * MINUTE_MS).default(5 * MINUTE_MS),
    YARA_ENABLED: booleanStringSchema.default(true),
    YARA_BINARY: absolutePath.default('/usr/bin/yara'),
    YARA_RULES_PATH: filePath.default('/app/yara/index.yar'),
    YARA_TIMEOUT_MS: int(1_000, 30 * MINUTE_MS).default(2 * MINUTE_MS),
  })
  .superRefine((env, ctx) => {
    const disabled = env.DOWNLOAD_AUTOMATIC_SOURCES.filter(
      (source) => !env.DOWNLOAD_SOURCES_ENABLED.includes(source),
    );
    if (disabled.length > 0) {
      ctx.addIssue({
        code: 'custom',
        path: ['DOWNLOAD_AUTOMATIC_SOURCES'],
        message: `automatic sources must be enabled: ${disabled.join(', ')}`,
      });
    }
    if (env.NODE_ENV === 'production') {
      for (const key of ['DOWNLOAD_GITHUB_ARCHIVE_URL', 'DOWNLOAD_EXPLOIT_DB_URL'] as const) {
        if (new URL(env[key]).port !== '') {
          ctx.addIssue({
            code: 'custom',
            path: [key],
            message: 'must use the default https port in production',
          });
        }
      }
    }
  });

export type Env = z.infer<typeof envSchema>;

/** Validates configuration at startup and enforces that this service uses its own database. */
export function loadServiceEnv(source: EnvSource = process.env): Env {
  const env = loadEnv(envSchema, source);
  assertServiceOwnsDatabase(SERVICE_NAME, env.DATABASE_URL);
  return env;
}
