import type { Server } from 'node:http';

import type { DynamicModule, INestApplication, Type } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

import type { BaseServiceEnv } from '@cve/config';
import { createLogger, PinoNestLogger, type Logger } from '@cve/logger';

import { createServiceMetrics, startMetricsServer } from '../metrics/metrics.js';
import { configureServiceApp } from './configure-service-app.js';

export interface BootstrapServiceOptions {
  readonly service: string;
  readonly version: string;
  readonly env: BaseServiceEnv & { readonly PORT: number };
  /** Root module of the service. */
  readonly module: DynamicModule | Type;
}

export interface RunningService {
  readonly app: INestApplication;
  readonly logger: Logger;
}

export async function bootstrapService(options: BootstrapServiceOptions): Promise<RunningService> {
  const { env } = options;
  const logger = createLogger({
    service: options.service,
    level: env.LOG_LEVEL,
    pretty: env.NODE_ENV === 'development' && process.stdout.isTTY,
  });

  process.on('unhandledRejection', (reason) => {
    logger.fatal({ err: reason }, 'unhandled promise rejection');
    process.exitCode = 1;
  });

  const app = await NestFactory.create(options.module, {
    logger: new PinoNestLogger(logger),
    bodyParser: false,
  });

  const metrics =
    env.METRICS_PORT === undefined
      ? undefined
      : createServiceMetrics(options.service, options.version);

  configureServiceApp(app, {
    service: options.service,
    version: options.version,
    logger,
    corsAllowedOrigins: env.CORS_ALLOWED_ORIGINS,
    swaggerEnabled: env.SWAGGER_ENABLED,
    ...(metrics ? { metrics } : {}),
  });
  app.enableShutdownHooks();

  await app.listen(env.PORT, env.HOST);
  if (metrics && env.METRICS_PORT !== undefined) {
    const metricsServer = await startMetricsServer({
      metrics,
      port: env.METRICS_PORT,
      host: env.HOST,
      logger,
    });
    (app.getHttpServer() as Server).once('close', () => {
      metricsServer.close();
    });
  }
  logger.info({ port: env.PORT, host: env.HOST, version: options.version }, 'service started');
  return { app, logger };
}

/** Standard process entrypoint wrapper: logs startup failures as JSON and exits non-zero. */
export function runService(start: () => Promise<unknown>, service: string): void {
  start().catch((error: unknown) => {
    const logger = createLogger({ service });
    logger.fatal({ err: error }, 'service failed to start');
    process.exit(1);
  });
}
