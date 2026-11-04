import {
  booleanStringSchema,
  httpUrlSchema,
  loadEnv,
  serviceEnvSchema,
  type EnvSource,
} from '@cve/config';
import { SERVICE_DEFAULT_PORTS } from '@cve/contracts';
import { assertServiceOwnsDatabase } from '@cve/database';
import { z } from 'zod';

import { SERVICE_NAME, SERVICE_VERSION } from '../service.js';

const HOUR_MS = 60 * 60 * 1000;

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

const optionalTimestamp = z.iso
  .datetime({ offset: true })
  .transform((value) => new Date(value))
  .optional();

const int = (min: number, max: number) => z.coerce.number().int().min(min).max(max);

export const envSchema = serviceEnvSchema(SERVICE_DEFAULT_PORTS[SERVICE_NAME])
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
    /** Runs the BullMQ synchronisation workers and schedules. Disabled only in tests. */
    SYNC_WORKER_ENABLED: booleanStringSchema.default(true),

    // ---- synchronisation engine
    /** Keep raw upstream payloads where the source's terms permit it. */
    STORE_RAW_PAYLOADS: booleanStringSchema.default(true),
    SOURCE_HTTP_USER_AGENT: z
      .string()
      .trim()
      .min(1)
      .max(200)
      .default(`cve-intelligence-platform/${SERVICE_VERSION} (self-hosted)`),
    SOURCE_HTTP_TIMEOUT_MS: int(1_000, 600_000).default(60_000),
    SOURCE_HTTP_MAX_ATTEMPTS: int(1, 10).default(4),
    /** Maximum duration of one run; a run that times out resumes from its checkpoint. */
    SYNC_JOB_TIMEOUT_MS: int(60_000, 24 * HOUR_MS).default(3 * HOUR_MS),
    /** BullMQ attempts per synchronisation job (each attempt resumes the previous one). */
    SYNC_JOB_ATTEMPTS: int(1, 20).default(4),
    /** A running run without heartbeat for this long is abandoned and recovered. */
    SYNC_STALE_RUN_AFTER_MS: int(60_000, 6 * HOUR_MS).default(10 * 60_000),
    SYNC_RESUME_WINDOW_HOURS: int(1, 24 * 14).default(24),
    SYNC_MAINTENANCE_CRON: cronSchema.default('*/5 * * * *'),
    OUTBOX_RETENTION_DAYS: int(1, 365).default(7),

    // ---- NVD CVE API 2.0
    NVD_ENABLED: booleanStringSchema.default(true),
    NVD_API_URL: httpUrlSchema.default('https://services.nvd.nist.gov/rest/json/cves/2.0'),
    /** Raises the NVD quota from 5 to 50 requests per 30 seconds. */
    NVD_API_KEY: optionalSecret,
    NVD_SYNC_CRON: cronSchema.default('15 */2 * * *'),
    NVD_PAGE_SIZE: int(1, 2_000).default(2_000),
    /** First run only: start at this modification time; unset synchronises the whole catalog. */
    NVD_INITIAL_SYNC_FROM: optionalTimestamp,

    // ---- MITRE CVE List
    MITRE_CVE_ENABLED: booleanStringSchema.default(true),
    MITRE_CVE_API_URL: httpUrlSchema.default('https://cveawg.mitre.org/api'),
    MITRE_CVE_DELTA_LOG_URL: httpUrlSchema.default(
      'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json',
    ),
    MITRE_CVE_SYNC_CRON: cronSchema.default('5 * * * *'),
    MITRE_CVE_INITIAL_LOOKBACK_HOURS: int(1, 30 * 24).default(24),
    MITRE_CVE_REQUESTS_PER_MINUTE: int(1, 600).default(120),

    // ---- CISA KEV
    CISA_KEV_ENABLED: booleanStringSchema.default(true),
    CISA_KEV_FEED_URL: httpUrlSchema.default(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    ),
    CISA_KEV_SYNC_CRON: cronSchema.default('30 */4 * * *'),

    // ---- FIRST EPSS
    EPSS_ENABLED: booleanStringSchema.default(true),
    EPSS_API_URL: httpUrlSchema.default('https://api.first.org/data/v1/epss'),
    EPSS_SYNC_CRON: cronSchema.default('45 */6 * * *'),
    EPSS_PAGE_SIZE: int(1, 10_000).default(1_000),
    EPSS_REQUESTS_PER_MINUTE: int(1, 600).default(60),
    EPSS_MAX_BACKFILL_DAYS: int(1, 31).default(7),
    /** EPSS scores kept in this service; the CVE Service keeps its own history. */
    EPSS_RETENTION_DAYS: int(1, 3_650).default(30),

    // ---- GitHub Advisory Database
    GITHUB_ADVISORY_ENABLED: booleanStringSchema.default(true),
    GITHUB_API_URL: httpUrlSchema.default('https://api.github.com'),
    /** Fine-grained token without permissions (public data); raises the quota to 5 000/h. */
    GITHUB_TOKEN: optionalSecret,
    GITHUB_ADVISORY_SYNC_CRON: cronSchema.default('20 * * * *'),
    GITHUB_ADVISORY_INITIAL_LOOKBACK_DAYS: int(1, 3_650).default(30),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV !== 'production') return;
    // Credentials travel in headers: production must never talk to a source over plain HTTP.
    for (const key of [
      'NVD_API_URL',
      'MITRE_CVE_API_URL',
      'MITRE_CVE_DELTA_LOG_URL',
      'CISA_KEV_FEED_URL',
      'EPSS_API_URL',
      'GITHUB_API_URL',
    ] as const) {
      if (new URL(env[key]).protocol !== 'https:') {
        ctx.addIssue({ code: 'custom', path: [key], message: 'must use https in production' });
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
