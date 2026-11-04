import { loadEnv, objectStorageEnvSchema, serviceEnvSchema, type EnvSource } from '@cve/config';
import { SERVICE_DEFAULT_PORTS } from '@cve/contracts';
import { assertServiceOwnsDatabase } from '@cve/database';
import type { z } from 'zod';

import { SERVICE_NAME } from '../service.js';

export const envSchema = serviceEnvSchema(SERVICE_DEFAULT_PORTS[SERVICE_NAME]).extend(
  objectStorageEnvSchema.shape,
);

export type Env = z.infer<typeof envSchema>;

/** Validates configuration at startup and enforces that this service uses its own database. */
export function loadServiceEnv(source: EnvSource = process.env): Env {
  const env = loadEnv(envSchema, source);
  assertServiceOwnsDatabase(SERVICE_NAME, env.DATABASE_URL);
  return env;
}
