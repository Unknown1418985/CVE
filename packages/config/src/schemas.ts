import { z } from 'zod';

export const NODE_ENVIRONMENTS = ['development', 'test', 'production'] as const;
export const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;

export const nodeEnvSchema = z.enum(NODE_ENVIRONMENTS).default('development');
export const logLevelSchema = z.enum(LOG_LEVELS).default('info');

export const portSchema = z.coerce.number().int().min(1).max(65_535);

/** Parses "true"/"false"/"1"/"0" strictly; anything else is rejected. */
export const booleanStringSchema = z
  .enum(['true', 'false', '1', '0'])
  .transform((value) => value === 'true' || value === '1');

/** Parses a comma-separated list, trimming entries and dropping empty ones. */
export const commaSeparatedListSchema = z.string().transform((value) =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0),
);

/** URL restricted to the given protocols, e.g. `urlWithProtocols(['http:', 'https:'])`. */
export function urlWithProtocols(protocols: readonly string[]) {
  return z.url().refine((value) => protocols.includes(new URL(value).protocol), {
    message: `URL protocol must be one of: ${protocols.join(', ')}`,
  });
}

export const httpUrlSchema = urlWithProtocols(['http:', 'https:']);

/** Variables every HTTP service accepts. */
export const baseServiceEnvSchema = z.object({
  NODE_ENV: nodeEnvSchema,
  LOG_LEVEL: logLevelSchema,
  HOST: z.string().min(1).default('0.0.0.0'),
  CORS_ALLOWED_ORIGINS: commaSeparatedListSchema.default([]),
  SWAGGER_ENABLED: booleanStringSchema.default(false),
  HEALTH_CHECK_TIMEOUT_MS: z.coerce.number().int().min(100).max(30_000).default(2_000),
  /** Port of the internal Prometheus metrics listener; metrics are disabled when unset. */
  METRICS_PORT: portSchema.optional(),
});

export const databaseEnvSchema = z.object({
  DATABASE_URL: urlWithProtocols(['postgres:', 'postgresql:']),
});

export const redisEnvSchema = z.object({
  REDIS_URL: urlWithProtocols(['redis:', 'rediss:']),
});

export const rabbitmqEnvSchema = z.object({
  RABBITMQ_URL: urlWithProtocols(['amqp:', 'amqps:']),
});

const secretSchema = z.string().min(16, 'must be at least 16 characters');

/** S3-compatible object storage (MinIO) with per-service credentials. */
export const objectStorageEnvSchema = z.object({
  S3_ENDPOINT: httpUrlSchema,
  S3_REGION: z.string().min(1).default('us-east-1'),
  S3_ACCESS_KEY_ID: z.string().min(3),
  S3_SECRET_ACCESS_KEY: secretSchema,
  S3_FORCE_PATH_STYLE: booleanStringSchema.default(true),
});

/** OpenSearch over TLS with a service-specific user. */
export const searchEnvSchema = z.object({
  OPENSEARCH_URL: httpUrlSchema,
  OPENSEARCH_USERNAME: z.string().min(1),
  OPENSEARCH_PASSWORD: secretSchema,
  /** PEM bundle used to verify the OpenSearch certificate (the platform CA). */
  OPENSEARCH_CA_FILE: z.string().min(1).optional(),
});

/** Standard environment for a backend microservice that owns a database. */
export function serviceEnvSchema(defaultPort: number) {
  return baseServiceEnvSchema
    .extend({ PORT: portSchema.default(defaultPort) })
    .extend(databaseEnvSchema.shape)
    .extend(redisEnvSchema.shape)
    .extend(rabbitmqEnvSchema.shape);
}

export type BaseServiceEnv = z.infer<typeof baseServiceEnvSchema>;
export type ObjectStorageEnv = z.infer<typeof objectStorageEnvSchema>;
export type SearchEnv = z.infer<typeof searchEnvSchema>;
export type ServiceEnv = z.infer<ReturnType<typeof serviceEnvSchema>>;
