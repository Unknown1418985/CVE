import {
  baseServiceEnvSchema,
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
    RATE_LIMIT_TTL_MS: z.coerce.number().int().min(1_000).default(DEFAULT_RATE_LIMIT.ttlMs),
    RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(DEFAULT_RATE_LIMIT.limit),
  })
  .extend(serviceUrlShape);

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
