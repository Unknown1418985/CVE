import type { INestApplication } from '@nestjs/common';

import { createTokenVerifier } from '@cve/auth';
import { createLogger, type Logger } from '@cve/logger';
import { configureServiceApp, type HealthIndicator } from '@cve/shared';
import { buildServiceTestEnv, createHttpTestApp, type HttpTestApp } from '@cve/testing';
import type { TestTokenIssuer } from '@cve/testing/auth';

import { AppModule } from '../src/app.module.js';
import { loadServiceEnv, type Env } from '../src/config/env.js';
import { createConnectorRegistry } from '../src/connectors/registry.js';
import type { DiscoveryJobQueue, DiscoveryPayload } from '../src/discovery/discovery-jobs.js';
import { createPrismaClient, type PrismaClient } from '../src/persistence/prisma.js';
import { scoringSettings } from '../src/runtime.js';
import { SERVICE_NAME } from '../src/service.js';

export const silentLogger: Logger = createLogger({ service: SERVICE_NAME, level: 'silent' });

export function pocTestEnv(overrides: Record<string, string> = {}): Env {
  return loadServiceEnv(
    buildServiceTestEnv(SERVICE_NAME, {
      KEYCLOAK_URL: 'http://keycloak.test/auth',
      KEYCLOAK_PUBLIC_URL: 'http://keycloak.test/auth',
      OUTBOX_RELAY_ENABLED: 'false',
      EVENT_CONSUMERS_ENABLED: 'false',
      DISCOVERY_WORKER_ENABLED: 'false',
      GITHUB_API_URL: 'http://github.test',
      ...overrides,
    }),
  );
}

/**
 * A Prisma client for a server that does not exist. HTTP tests that stop at authentication,
 * authorization or validation never reach it; persistence is covered by the integration suite.
 */
export function unreachablePrisma(): PrismaClient {
  return createPrismaClient('postgresql://poc_service:unused@127.0.0.1:9/poc_service');
}

/** Records queued jobs instead of sending them to Redis. */
export class FakeJobQueue implements DiscoveryJobQueue {
  readonly discovery: { payload: DiscoveryPayload; jobId: string | undefined }[] = [];
  readonly inspections: { repositoryId: string; dedupeKey: string }[] = [];
  private readonly ids = new Set<string>();

  enqueueDiscovery(payload: DiscoveryPayload, jobId?: string) {
    const id = jobId ?? `job-${String(this.discovery.length + 1)}`;
    if (this.ids.has(id)) return Promise.resolve({ jobId: id, queued: false });
    this.ids.add(id);
    this.discovery.push({ payload, jobId });
    return Promise.resolve({ jobId: id, queued: true });
  }

  enqueueInspection(input: { repositoryId: string; dedupeKey: string }) {
    const id = `${input.repositoryId}:${input.dedupeKey}`;
    if (this.ids.has(id)) return Promise.resolve(false);
    this.ids.add(id);
    this.inspections.push({ repositoryId: input.repositoryId, dedupeKey: input.dedupeKey });
    return Promise.resolve(true);
  }
}

export async function startPocApp(
  issuer: TestTokenIssuer,
  options: {
    prisma?: PrismaClient;
    jobs?: DiscoveryJobQueue | null;
    healthIndicators?: readonly HealthIndicator[];
  } = {},
): Promise<HttpTestApp> {
  const env = pocTestEnv();
  return createHttpTestApp(
    AppModule.register(env, {
      logger: silentLogger,
      verifier: createTokenVerifier({
        issuer: issuer.issuer,
        audience: issuer.audience,
        keys: issuer.getKey,
      }),
      prisma: options.prisma ?? unreachablePrisma(),
      healthIndicators: options.healthIndicators ?? [],
      jobs: options.jobs === undefined ? new FakeJobQueue() : options.jobs,
      connectors: createConnectorRegistry(env, { logger: silentLogger }).info,
      scoring: scoringSettings(env),
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
}

/** Builders of GitHub API payloads (synthetic data only). */
export function githubRepo(
  overrides: Record<string, unknown> & { id: number; name: string; owner?: string },
) {
  const owner = overrides.owner ?? 'zz-test-owner';
  const rest: Record<string, unknown> = { ...overrides };
  delete rest['owner'];
  return {
    full_name: `${owner}/${overrides.name}`,
    private: false,
    owner: { login: owner, id: 9_000_000 + overrides.id, type: 'User' },
    description: null,
    fork: false,
    created_at: '2026-01-02T00:00:00Z',
    pushed_at: '2026-10-01T00:00:00Z',
    size: 12,
    stargazers_count: 3,
    forks_count: 1,
    language: 'Python',
    topics: [],
    archived: false,
    default_branch: 'main',
    ...rest,
  };
}

export const sha = (seed: string) =>
  Array.from(
    { length: 40 },
    (_, index) => '0123456789abcdef'[(seed.charCodeAt(index % seed.length) + index) % 16],
  ).join('');
