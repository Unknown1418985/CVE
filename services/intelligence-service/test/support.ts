import type { IntelligenceSource } from '@cve/contracts';
import { createLogger, type Logger } from '@cve/logger';
import { buildServiceTestEnv } from '@cve/testing';

import { loadServiceEnv, type Env } from '../src/config/env.js';
import type { IntelligenceRepository } from '../src/persistence/ports.js';
import { SERVICE_NAME } from '../src/service.js';
import {
  createSourceRegistry,
  enabledAdapters,
  type RegisteredSource,
} from '../src/sources/registry.js';
import { SyncEngine, type RunOutcome, type RunRequest } from '../src/sync/sync-engine.js';
import type { MockSource } from './mock-source.js';

export const silentLogger: Logger = createLogger({ service: SERVICE_NAME, level: 'silent' });

/** Points every source at the mock server (plain HTTP is allowed outside production). */
export function intelligenceTestEnv(
  mock: MockSource | null,
  overrides: Record<string, string> = {},
): Env {
  const origin = mock?.origin ?? 'http://source.test';
  return loadServiceEnv(
    buildServiceTestEnv(SERVICE_NAME, {
      KEYCLOAK_URL: 'http://keycloak.test/auth',
      KEYCLOAK_PUBLIC_URL: 'http://keycloak.test/auth',
      OUTBOX_RELAY_ENABLED: 'false',
      SYNC_WORKER_ENABLED: 'false',
      NVD_API_URL: `${origin}/rest/json/cves/2.0`,
      MITRE_CVE_API_URL: `${origin}/api`,
      MITRE_CVE_DELTA_LOG_URL: `${origin}/cvelist/deltaLog.json`,
      CISA_KEV_FEED_URL: `${origin}/feeds/known_exploited_vulnerabilities.json`,
      EPSS_API_URL: `${origin}/data/v1/epss`,
      GITHUB_API_URL: origin,
      SOURCE_HTTP_TIMEOUT_MS: '2000',
      SOURCE_HTTP_MAX_ATTEMPTS: '3',
      ...overrides,
    }),
  );
}

const FAST = { maxRequests: 1_000, windowMs: 1_000 };

export function testRegistry(env: Env): ReadonlyMap<IntelligenceSource, RegisteredSource> {
  return createSourceRegistry(env, {
    logger: silentLogger,
    retryBaseDelayMs: 5,
    rateLimits: {
      nvd: FAST,
      'mitre-cve': FAST,
      'cisa-kev': FAST,
      'first-epss': FAST,
      'github-advisory': FAST,
    },
  });
}

export function testEngine(
  repository: IntelligenceRepository,
  env: Env,
  options: { now?: () => Date; leaseMs?: number } = {},
): SyncEngine {
  return new SyncEngine({
    repository,
    adapters: enabledAdapters(testRegistry(env)),
    logger: silentLogger,
    instanceId: 'test-worker',
    storeRawPayloads: env.STORE_RAW_PAYLOADS,
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.leaseMs === undefined ? {} : { leaseMs: options.leaseMs }),
  });
}

let jobCounter = 0;

export function runSource(
  engine: SyncEngine,
  source: IntelligenceSource,
  overrides: Partial<RunRequest> = {},
  signal: AbortSignal = new AbortController().signal,
): Promise<RunOutcome> {
  jobCounter += 1;
  return engine.run(
    {
      source,
      trigger: 'manual',
      jobId: `test.${String(jobCounter)}`,
      attempt: 1,
      maxAttempts: 1,
      requestedBy: 'test',
      fresh: false,
      ...overrides,
    },
    signal,
  );
}

export function expectSucceeded(outcome: RunOutcome) {
  if (outcome.status !== 'succeeded') {
    throw new Error(
      `expected success, got ${outcome.status}${outcome.status === 'failed' ? `: ${outcome.error.message}` : ''}`,
    );
  }
  return outcome.run;
}
