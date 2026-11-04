import type { DynamicModule, INestApplication, Type } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

export interface HttpTestApp {
  readonly app: INestApplication;
  /** Supertest agent bound to the app's HTTP server. */
  readonly http: ReturnType<typeof request>;
  close(): Promise<void>;
}

/**
 * Compiles `module`, applies `configure` (normally the production HTTP configuration),
 * initialises the app and returns a Supertest client. Nothing listens on a real port.
 */
export async function createHttpTestApp(
  module: DynamicModule | Type,
  configure?: (app: INestApplication) => void,
): Promise<HttpTestApp> {
  const moduleRef = await Test.createTestingModule({ imports: [module] }).compile();
  const app = moduleRef.createNestApplication({ logger: false });
  configure?.(app);
  await app.init();
  return {
    app,
    http: request(app.getHttpServer() as Parameters<typeof request>[0]),
    close: () => app.close(),
  };
}
