import type { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import type { Express } from 'express';
import express from 'express';

import { API_PREFIX, CORRELATION_ID_HEADER } from '@cve/contracts';
import type { Logger } from '@cve/logger';
import { buildCorsOptions, createSecurityHeadersMiddleware } from '@cve/security';

import { ApiExceptionFilter } from '../http/api-exception.filter.js';
import { createRequestContextMiddleware } from '../http/correlation-id.js';
import { createHttpMetricsMiddleware, type ServiceMetrics } from '../metrics/metrics.js';

export interface ConfigureServiceAppOptions {
  readonly service: string;
  readonly version: string;
  readonly logger: Logger;
  readonly corsAllowedOrigins: readonly string[];
  readonly swaggerEnabled: boolean;
  /** Maximum accepted JSON body size. */
  readonly bodyLimit?: string;
  /** Records HTTP request metrics when provided. */
  readonly metrics?: ServiceMetrics;
}

export const DOCS_PATH = `${API_PREFIX}/docs`;

/**
 * Applies the platform-wide HTTP conventions: `/api/v1` prefix, security headers, strict CORS,
 * correlation IDs, request logging, body limits, error envelopes and optional OpenAPI docs.
 * Used by `bootstrapService` and by HTTP tests so both exercise the same configuration.
 */
export function configureServiceApp(
  app: INestApplication,
  options: ConfigureServiceAppOptions,
): void {
  const server = app.getHttpAdapter().getInstance() as Express;
  server.disable('x-powered-by');
  server.set('trust proxy', 'loopback, linklocal, uniquelocal');

  if (options.metrics) {
    app.use(createHttpMetricsMiddleware(options.metrics));
  }
  app.use(createSecurityHeadersMiddleware({ docsPathPrefixes: [`/${DOCS_PATH}`] }));
  app.use(
    createRequestContextMiddleware({
      logger: options.logger,
      quietPathPrefixes: [`/${API_PREFIX}/health`],
    }),
  );
  app.use(express.json({ limit: options.bodyLimit ?? '1mb' }));

  app.enableCors(buildCorsOptions(options.corsAllowedOrigins));
  app.setGlobalPrefix(API_PREFIX);
  app.useGlobalFilters(new ApiExceptionFilter(options.logger));

  if (options.swaggerEnabled) {
    const document = SwaggerModule.createDocument(
      app,
      new DocumentBuilder()
        .setTitle(`${options.service} API`)
        .setVersion(options.version)
        .addGlobalParameters({
          name: CORRELATION_ID_HEADER,
          in: 'header',
          required: false,
          schema: { type: 'string' },
        })
        .build(),
    );
    SwaggerModule.setup(DOCS_PATH, app, document);
  }
}
