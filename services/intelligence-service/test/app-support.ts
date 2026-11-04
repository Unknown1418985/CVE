import type { INestApplication } from '@nestjs/common';

import { createTokenVerifier } from '@cve/auth';
import { configureServiceApp, type HealthIndicator } from '@cve/shared';
import { createHttpTestApp, type HttpTestApp } from '@cve/testing';
import type { TestTokenIssuer } from '@cve/testing/auth';

import { AppModule } from '../src/app.module.js';
import type { Env } from '../src/config/env.js';
import { SERVICE_NAME } from '../src/service.js';
import type { SourceSyncPayload, SyncJobQueue } from '../src/sync/sync-jobs.js';
import { InMemoryIntelligenceRepository } from './in-memory-repository.js';
import { intelligenceTestEnv, silentLogger, testRegistry } from './support.js';

/** Records queued jobs; an existing job ID is not queued twice (like BullMQ). */
export class FakeJobQueue implements SyncJobQueue {
  readonly jobs = new Map<string, SourceSyncPayload>();
  private counter = 0;

  enqueue(payload: SourceSyncPayload, jobId?: string) {
    this.counter += 1;
    const id = jobId ?? `${payload.trigger}.${payload.source}.${String(this.counter)}`;
    if (this.jobs.has(id)) return Promise.resolve({ jobId: id, queued: false });
    this.jobs.set(id, payload);
    return Promise.resolve({ jobId: id, queued: true });
  }
}

export interface AppContext {
  readonly t: HttpTestApp;
  readonly repository: InMemoryIntelligenceRepository;
  readonly jobs: FakeJobQueue;
  readonly env: Env;
}

export async function startApp(
  issuer: TestTokenIssuer | null,
  options: { env?: Env; healthIndicators?: readonly HealthIndicator[] } = {},
): Promise<AppContext> {
  const env = options.env ?? intelligenceTestEnv(null);
  const repository = new InMemoryIntelligenceRepository();
  const jobs = new FakeJobQueue();
  const verifier =
    issuer === null
      ? createTokenVerifier({
          issuer: 'http://keycloak.test/auth/realms/cve-platform',
          audience: 'cve-api',
          keys: { jwksUrl: 'http://keycloak.test/jwks', timeoutMs: 500 },
        })
      : createTokenVerifier({
          issuer: issuer.issuer,
          audience: issuer.audience,
          keys: issuer.getKey,
        });
  const t = await createHttpTestApp(
    AppModule.register(env, {
      logger: silentLogger,
      verifier,
      repository,
      registry: testRegistry(env),
      jobs,
      healthIndicators: options.healthIndicators ?? [],
    }),
    (app: INestApplication) => {
      configureServiceApp(app, {
        service: SERVICE_NAME,
        version: '0.0.0-test',
        logger: silentLogger,
        corsAllowedOrigins: [],
        swaggerEnabled: false,
      });
    },
  );
  return { t, repository, jobs, env };
}
