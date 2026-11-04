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

import { SERVICE_NAME } from '../service.js';

const secretSchema = z.string().min(16, 'must be at least 16 characters');

export const envSchema = serviceEnvSchema(SERVICE_DEFAULT_PORTS[SERVICE_NAME]).extend({
  /** Internal Keycloak base URL including the relative path, e.g. `http://keycloak:8180/auth`. */
  KEYCLOAK_URL: httpUrlSchema,
  /** Public Keycloak base URL that browsers use; it defines the token issuer. */
  KEYCLOAK_PUBLIC_URL: httpUrlSchema,
  KEYCLOAK_REALM: z
    .string()
    .regex(/^[A-Za-z0-9_-]{1,64}$/)
    .default('cve-platform'),
  /** Audience every access token must contain. */
  KEYCLOAK_AUDIENCE: z.string().min(1).default('cve-api'),
  /** Service-account client used for the Keycloak Admin REST API. */
  KEYCLOAK_ADMIN_CLIENT_ID: z.string().min(1).default('cve-identity-service'),
  KEYCLOAK_ADMIN_CLIENT_SECRET: secretSchema,
  /** Browser client used for credential actions (password change, TOTP setup). */
  KEYCLOAK_WEB_CLIENT_ID: z.string().min(1).default('cve-web'),
  /** Where Keycloak sends the browser back after a credential action. */
  ACCOUNT_REDIRECT_URI: httpUrlSchema,
  KEYCLOAK_TIMEOUT_MS: z.coerce.number().int().min(500).max(30_000).default(5_000),
  /** Publishes outbox events to RabbitMQ. Disabled only in tests. */
  OUTBOX_RELAY_ENABLED: booleanStringSchema.default(true),
  /** Ingests Keycloak login and admin events into the audit log. */
  KEYCLOAK_EVENTS_SYNC_ENABLED: booleanStringSchema.default(true),
  KEYCLOAK_EVENTS_SYNC_INTERVAL_MS: z.coerce.number().int().min(10_000).default(60_000),
});

export type Env = z.infer<typeof envSchema>;

/** Validates configuration at startup and enforces that this service uses its own database. */
export function loadServiceEnv(source: EnvSource = process.env): Env {
  const env = loadEnv(envSchema, source);
  assertServiceOwnsDatabase(SERVICE_NAME, env.DATABASE_URL);
  return env;
}
