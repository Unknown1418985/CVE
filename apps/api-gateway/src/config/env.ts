import {
  baseServiceEnvSchema,
  booleanStringSchema,
  httpUrlSchema,
  loadEnv,
  portSchema,
  type EnvSource,
} from '@cve/config';
import {
  BACKEND_SERVICE_NAMES,
  SERVICE_DEFAULT_PORTS,
  type BackendServiceName,
} from '@cve/contracts';
import { DEFAULT_RATE_LIMIT } from '@cve/security';
import { z } from 'zod';

import { SERVICE_NAME } from '../service.js';

type SnakeCase<S extends string> = S extends `${infer Head}-${infer Tail}`
  ? `${Head}_${SnakeCase<Tail>}`
  : S;

/** `cve-service` → `CVE_SERVICE_URL` */
export function serviceUrlVariable(service: BackendServiceName): string {
  return `${service.toUpperCase().replaceAll('-', '_')}_URL`;
}

/** One required base URL per backend service. Kept explicit so the inferred type is exact. */
const serviceUrlShape = {
  IDENTITY_SERVICE_URL: httpUrlSchema,
  CVE_SERVICE_URL: httpUrlSchema,
  INTELLIGENCE_SERVICE_URL: httpUrlSchema,
  ASSET_SERVICE_URL: httpUrlSchema,
  POC_SERVICE_URL: httpUrlSchema,
  DOWNLOAD_SERVICE_URL: httpUrlSchema,
  EXPLOIT_SERVICE_URL: httpUrlSchema,
  REPORTING_SERVICE_URL: httpUrlSchema,
  NOTIFICATION_SERVICE_URL: httpUrlSchema,
} satisfies Record<`${Uppercase<SnakeCase<BackendServiceName>>}_URL`, typeof httpUrlSchema>;

export const envSchema = baseServiceEnvSchema
  .extend({
    PORT: portSchema.default(SERVICE_DEFAULT_PORTS[SERVICE_NAME]),
    /** Requests per window, per authenticated user (or per client IP when anonymous). */
    RATE_LIMIT_TTL_MS: z.coerce.number().int().min(1_000).default(DEFAULT_RATE_LIMIT.ttlMs),
    RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(DEFAULT_RATE_LIMIT.limit),
    /** Internal Keycloak base URL, e.g. `http://keycloak:8180/auth` (JWKS, introspection). */
    KEYCLOAK_URL: httpUrlSchema,
    /** Public Keycloak base URL; defines the expected token issuer. */
    KEYCLOAK_PUBLIC_URL: httpUrlSchema,
    KEYCLOAK_REALM: z
      .string()
      .regex(/^[A-Za-z0-9_-]{1,64}$/)
      .default('cve-platform'),
    KEYCLOAK_AUDIENCE: z.string().min(1).default('cve-api'),
    KEYCLOAK_TIMEOUT_MS: z.coerce.number().int().min(500).max(30_000).default(5_000),
    /**
     * Confirms on every request (cached briefly per session) that the Keycloak session behind a
     * token is still active, so logout and revocation apply before the access token expires.
     */
    AUTH_SESSION_CHECK_ENABLED: booleanStringSchema.default(true),
    AUTH_SESSION_CACHE_TTL_MS: z.coerce.number().int().min(1_000).max(60_000).default(15_000),
    /** Confidential resource-server client used for token introspection. */
    KEYCLOAK_INTROSPECTION_CLIENT_ID: z.string().min(1).default('cve-api'),
    KEYCLOAK_INTROSPECTION_CLIENT_SECRET: z.string().min(16).optional(),
    /** Timeout for requests forwarded to backend services. */
    PROXY_TIMEOUT_MS: z.coerce.number().int().min(500).max(120_000).default(15_000),
  })
  .extend(serviceUrlShape)
  .superRefine((env, context) => {
    if (env.AUTH_SESSION_CHECK_ENABLED && env.KEYCLOAK_INTROSPECTION_CLIENT_SECRET === undefined) {
      context.addIssue({
        code: 'custom',
        path: ['KEYCLOAK_INTROSPECTION_CLIENT_SECRET'],
        message: 'is required while AUTH_SESSION_CHECK_ENABLED=true',
      });
    }
  });

export type Env = z.infer<typeof envSchema>;

export type ServiceRegistry = Readonly<Record<BackendServiceName, string>>;

export function loadGatewayEnv(source: EnvSource = process.env): Env {
  return loadEnv(envSchema, source);
}

/** Base URLs of the backend services, without trailing slashes. */
export function serviceRegistryFromEnv(env: Env): ServiceRegistry {
  const values = env as unknown as Readonly<Record<string, string>>;
  return Object.fromEntries(
    BACKEND_SERVICE_NAMES.map((service) => {
      const url = values[serviceUrlVariable(service)];
      if (url === undefined) {
        throw new Error(`Missing ${serviceUrlVariable(service)}`);
      }
      return [service, url.replace(/\/+$/, '')];
    }),
  ) as Record<BackendServiceName, string>;
}
