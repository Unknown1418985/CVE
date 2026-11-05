import {
  booleanStringSchema,
  httpUrlSchema,
  loadEnv,
  objectStorageEnvSchema,
  serviceEnvSchema,
  type EnvSource,
} from '@cve/config';
import { POC_CONNECTORS, SERVICE_DEFAULT_PORTS, type PocConnector } from '@cve/contracts';
import { assertServiceOwnsDatabase } from '@cve/database';
import { z } from 'zod';

import { SERVICE_NAME, SERVICE_VERSION } from '../service.js';

const MINUTE_MS = 60_000;

/** Five-field cron expression, evaluated in UTC by BullMQ. */
const cronSchema = z
  .string()
  .trim()
  .regex(/^(\S+\s+){4}\S+$/, { message: 'must be a five-field cron expression' });

/** Optional secret; `loadEnv` drops empty values, so unset or empty means "not configured". */
const optionalSecret = z
  .string()
  .trim()
  .min(16, 'must be at least 16 characters')
  .max(256)
  .optional();

const int = (min: number, max: number) => z.coerce.number().int().min(min).max(max);

/** Comma-separated list of approved connectors (unknown names are refused at startup). */
const connectorListSchema = z
  .string()
  .trim()
  .transform((value, ctx): PocConnector[] => {
    const names =
      value === '' || value === 'none' ? [] : value.split(',').map((name) => name.trim());
    const unknown = names.filter((name) => !(POC_CONNECTORS as readonly string[]).includes(name));
    if (unknown.length > 0) {
      ctx.addIssue({
        code: 'custom',
        message: `not approved connectors: ${unknown.join(', ')} (approved: ${POC_CONNECTORS.join(', ')})`,
      });
      return z.NEVER;
    }
    return [...new Set(names)] as PocConnector[];
  });

const SEARCH_FIELDS = ['name', 'description', 'topics', 'readme'] as const;

export const envSchema = serviceEnvSchema(SERVICE_DEFAULT_PORTS[SERVICE_NAME])
  .extend(objectStorageEnvSchema.shape)
  .extend({
    /** Internal Keycloak base URL including the relative path; used to fetch the realm JWKS. */
    KEYCLOAK_URL: httpUrlSchema,
    /** Public Keycloak base URL that browsers use; it defines the token issuer. */
    KEYCLOAK_PUBLIC_URL: httpUrlSchema,
    KEYCLOAK_REALM: z
      .string()
      .regex(/^[A-Za-z0-9_-]{1,64}$/)
      .default('cve-platform'),
    KEYCLOAK_AUDIENCE: z.string().min(1).default('cve-api'),
    KEYCLOAK_TIMEOUT_MS: int(500, 30_000).default(5_000),
    /** Publishes outbox events to RabbitMQ. Disabled only in tests. */
    OUTBOX_RELAY_ENABLED: booleanStringSchema.default(true),
    /** Consumes `cve.record.*` and `intelligence.cve-observation.recorded`. Disabled only in tests. */
    EVENT_CONSUMERS_ENABLED: booleanStringSchema.default(true),
    /** Runs the BullMQ discovery workers and schedules. Disabled only in tests. */
    DISCOVERY_WORKER_ENABLED: booleanStringSchema.default(true),

    // ---- connectors
    /** Approved connectors enabled on this deployment (comma-separated, or `none`). */
    POC_CONNECTORS_ENABLED: connectorListSchema.default(['github', 'cve-references']),
    SOURCE_HTTP_USER_AGENT: z
      .string()
      .trim()
      .min(1)
      .max(200)
      .default(`cve-intelligence-platform/${SERVICE_VERSION} (self-hosted)`),
    SOURCE_HTTP_TIMEOUT_MS: int(1_000, 300_000).default(30_000),
    SOURCE_HTTP_MAX_ATTEMPTS: int(1, 10).default(4),
    GITHUB_API_URL: httpUrlSchema.default('https://api.github.com'),
    /** Fine-grained token without permissions (public data); raises the quotas. */
    GITHUB_TOKEN: optionalSecret,
    POC_GITHUB_SEARCH_IN: z
      .string()
      .trim()
      .default('name,description,topics,readme')
      .transform((value) => value.split(',').map((field) => field.trim()))
      .pipe(z.array(z.enum(SEARCH_FIELDS)).min(1)),
    POC_GITHUB_MAX_SEARCH_PAGES: int(1, 10).default(3),
    /** Sweep of repositories pushed recently that mention CVEs. */
    POC_GITHUB_RECENT_CRON: cronSchema.default('*/30 * * * *'),
    /** Width of one window of the recent sweep (halved when GitHub reports > 1 000 results). */
    POC_GITHUB_RECENT_WINDOW_MINUTES: int(5, 24 * 60).default(60),
    /** First recent sweep: look back this far. */
    POC_GITHUB_RECENT_INITIAL_LOOKBACK_HOURS: int(1, 24 * 30).default(24),
    POC_GITHUB_RECENT_MAX_WINDOWS_PER_RUN: int(1, 200).default(24),

    // ---- discovery
    /** Tracked CVEs whose scan is due are queued by this schedule. */
    POC_DISCOVERY_SWEEP_CRON: cronSchema.default('*/10 * * * *'),
    POC_DISCOVERY_BATCH_SIZE: int(1, 500).default(20),
    /** Associations scoring below this are not stored. */
    POC_MIN_ASSOCIATION_CONFIDENCE: z.coerce.number().min(0).max(1).default(0.15),
    POC_MAX_ASSOCIATIONS_PER_REPOSITORY: int(1, 500).default(50),
    /** File entries stored per artifact (the fingerprint always covers the whole listing). */
    POC_MAX_FILES_PER_ARTIFACT: int(10, 20_000).default(2_000),
    /** Significant shared blobs (Jaccard) for a near-duplicate. */
    POC_NEAR_DUPLICATE_THRESHOLD: z.coerce.number().min(0.5).max(1).default(0.8),
    POC_DISCOVERY_JOB_ATTEMPTS: int(1, 20).default(4),
    POC_DISCOVERY_JOB_TIMEOUT_MS: int(MINUTE_MS, 6 * 60 * MINUTE_MS).default(30 * MINUTE_MS),
    POC_INSPECTION_CONCURRENCY: int(1, 16).default(2),
    POC_MAINTENANCE_CRON: cronSchema.default('7 * * * *'),
    PROCESSED_EVENT_RETENTION_DAYS: int(1, 365).default(30),
    OUTBOX_RETENTION_DAYS: int(1, 365).default(7),
    DISCOVERY_RUN_RETENTION_DAYS: int(1, 3_650).default(90),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production' && new URL(env.GITHUB_API_URL).protocol !== 'https:') {
      // The token travels in a header: production must never call GitHub over plain HTTP.
      ctx.addIssue({
        code: 'custom',
        path: ['GITHUB_API_URL'],
        message: 'must use https in production',
      });
    }
  });

export type Env = z.infer<typeof envSchema>;

/** Validates configuration at startup and enforces that this service uses its own database. */
export function loadServiceEnv(source: EnvSource = process.env): Env {
  const env = loadEnv(envSchema, source);
  assertServiceOwnsDatabase(SERVICE_NAME, env.DATABASE_URL);
  return env;
}
