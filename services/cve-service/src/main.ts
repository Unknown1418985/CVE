import 'reflect-metadata';

import { bootstrapService, runService } from '@cve/shared';

import { AppModule } from './app.module.js';
import { loadServiceEnv } from './config/env.js';
import { SERVICE_NAME, SERVICE_VERSION } from './service.js';

runService(async () => {
  const env = loadServiceEnv();
  await bootstrapService({
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    env,
    module: AppModule.register(env),
  });
}, SERVICE_NAME);
