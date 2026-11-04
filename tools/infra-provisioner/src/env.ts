import {
  commaSeparatedListSchema,
  httpUrlSchema,
  loadEnv,
  logLevelSchema,
  type EnvSource,
} from '@cve/config';
import type { BackendServiceName } from '@cve/contracts';
import { z } from 'zod';

export const PROVISION_TARGETS = ['rabbitmq', 'opensearch'] as const;
export type ProvisionTarget = (typeof PROVISION_TARGETS)[number];

const secretSchema = z.string().min(16, 'must be at least 16 characters');

/** `cve-service` → `CVE_SERVICE_RABBITMQ_PASSWORD` */
export function rabbitPasswordVariable(service: BackendServiceName): string {
  return `${service.toUpperCase().replaceAll('-', '_')}_RABBITMQ_PASSWORD`;
}

type SnakeCase<S extends string> = S extends `${infer Head}-${infer Tail}`
  ? `${Head}_${SnakeCase<Tail>}`
  : S;

/** One RabbitMQ password per backend service; explicit so the inferred type is exact. */
const servicePasswordShape = {
  IDENTITY_SERVICE_RABBITMQ_PASSWORD: secretSchema,
  CVE_SERVICE_RABBITMQ_PASSWORD: secretSchema,
  INTELLIGENCE_SERVICE_RABBITMQ_PASSWORD: secretSchema,
  ASSET_SERVICE_RABBITMQ_PASSWORD: secretSchema,
  POC_SERVICE_RABBITMQ_PASSWORD: secretSchema,
  DOWNLOAD_SERVICE_RABBITMQ_PASSWORD: secretSchema,
  EXPLOIT_SERVICE_RABBITMQ_PASSWORD: secretSchema,
  REPORTING_SERVICE_RABBITMQ_PASSWORD: secretSchema,
  NOTIFICATION_SERVICE_RABBITMQ_PASSWORD: secretSchema,
} satisfies Record<
  `${Uppercase<SnakeCase<BackendServiceName>>}_RABBITMQ_PASSWORD`,
  typeof secretSchema
>;

export const envSchema = z
  .object({
    LOG_LEVEL: logLevelSchema,
    PROVISION_TARGETS: commaSeparatedListSchema
      .default(['rabbitmq', 'opensearch'])
      .pipe(z.array(z.enum(PROVISION_TARGETS)).min(1)),
    PROVISION_WAIT_TIMEOUT_MS: z.coerce.number().int().min(1_000).default(180_000),
    HTTP_TIMEOUT_MS: z.coerce.number().int().min(500).default(10_000),

    RABBITMQ_MANAGEMENT_URL: httpUrlSchema.default('http://rabbitmq:15672'),
    RABBITMQ_ADMIN_USER: z.string().min(1),
    RABBITMQ_ADMIN_PASSWORD: secretSchema,

    OPENSEARCH_URL: httpUrlSchema.default('https://opensearch:9200'),
    OPENSEARCH_ADMIN_USER: z.string().min(1).default('admin'),
    OPENSEARCH_ADMIN_PASSWORD: secretSchema,
    OPENSEARCH_CA_FILE: z.string().min(1).default('/run/platform-ca/platform-ca.pem'),
    CVE_SERVICE_OPENSEARCH_PASSWORD: secretSchema,
  })
  .extend(servicePasswordShape);

export type Env = z.infer<typeof envSchema>;

export function loadProvisionerEnv(source: EnvSource = process.env): Env {
  return loadEnv(envSchema, source);
}

export function rabbitPasswordFor(env: Env, service: BackendServiceName): string {
  const variable = rabbitPasswordVariable(service) as keyof typeof servicePasswordShape;
  return env[variable];
}
