import 'reflect-metadata';

import { createLogger } from '@cve/logger';
import { bootstrapService, runService } from '@cve/shared';

import { AppModule } from './app.module.js';
import { loadServiceEnv } from './config/env.js';
import { createRuntimeDependencies } from './runtime.js';
import { SERVICE_NAME, SERVICE_VERSION } from './service.js';

runService(async () => {
  const env = loadServiceEnv();
  const logger = createLogger({ service: SERVICE_NAME, level: env.LOG_LEVEL });
  await bootstrapService({
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    env,
    module: AppModule.register(env, createRuntimeDependencies(env, logger)),
  });
}, SERVICE_NAME);
