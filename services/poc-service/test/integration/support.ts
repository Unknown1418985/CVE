import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';

import {
  CVE_EVENT_TYPES,
  cveObservationRecordedPayloadSchema,
  INTELLIGENCE_EVENT_TYPES,
  type CveObservationRecordedPayload,
  type CveRecordCreatedPayload,
} from '@cve/contracts';
import type { DomainEvent } from '@cve/messaging';
import { integrationHost, requireEnv, serviceRedisUrl } from '@cve/testing/integration';

import type { Env } from '../../src/config/env.js';
import { createConnectorRegistry } from '../../src/connectors/registry.js';
import { DiscoveryEngine, type DiscoveryRequest } from '../../src/discovery/discovery-engine.js';
import type { DiscoveryJobQueue } from '../../src/discovery/discovery-jobs.js';
import type { CveRecordEvent } from '../../src/events/cve-tracker.js';
import type { PrismaClient } from '../../src/persistence/prisma.js';
import { discoverySettings } from '../../src/runtime.js';
import type { MockSource } from '../mock-source.js';
import { githubRepo, pocTestEnv, silentLogger } from '../support.js';

/**
 * Database URL of the poc-service role on the dev-published PostgreSQL. Override with
 * `POC_SERVICE_TEST_DATABASE_URL` to use another server.
 */
export function pocDatabaseUrl(): string {
  const override = process.env['POC_SERVICE_TEST_DATABASE_URL'];
  if (override !== undefined && override !== '') return override;
  const password = encodeURIComponent(requireEnv('POC_SERVICE_DB_PASSWORD'));
  return `postgresql://poc_service:${password}@${integrationHost()}:5432/poc_service`;
}

/** Redis URL of the poc-service ACL user (override: `POC_SERVICE_TEST_REDIS_URL`). */
export function pocRedisUrl(): string {
  const override = process.env['POC_SERVICE_TEST_REDIS_URL'];
  return override !== undefined && override !== '' ? override : serviceRedisUrl('poc-service');
}

/** Applies the committed migrations exactly as the `poc-service-migrate` job does. */
export function migrate(databaseUrl: string): void {
  execFileSync('pnpm', ['exec', 'prisma', 'migrate', 'deploy'], {
    cwd: resolve(import.meta.dirname, '../..'),
    env: { ...process.env, DATABASE_URL: databaseUrl },
    stdio: 'pipe',
  });
}

/**
 * Synthetic test data only: repository owners start with `zz-test`, CVE IDs are
 * `CVE-2026-9xxxxx`. Nothing here describes a real repository or vulnerability.
 */
export const syntheticCveId = (n: number) => `CVE-2026-${String(900_000 + n)}`;
export const TEST_OWNER = 'zz-test-owner';

/**
 * Empties the service tables between tests. Refuses to run against a database holding data this
 * suite did not create (non-synthetic owners or CVEs).
 */
export async function resetDatabase(prisma: PrismaClient): Promise<void> {
  const [foreign] = await prisma.$queryRaw<{ owners: bigint; cves: bigint }[]>`
    SELECT (SELECT count(*) FROM "repository_owners" WHERE "login" NOT LIKE 'zz-test%') AS "owners",
           (SELECT count(*) FROM "tracked_cves" WHERE "cve_id" !~ '^CVE-2026-9[0-9]{5}$') AS "cves"`;
  if (foreign === undefined || foreign.owners > 0n || foreign.cves > 0n) {
    throw new Error(
      'The poc_service database contains data this suite did not create; run the integration tests against a disposable database.',
    );
  }
  await prisma.$executeRaw`
    TRUNCATE "artifact_verification_events", "artifact_files", "repository_commits",
             "poc_cve_associations", "poc_references", "poc_artifacts", "poc_repositories",
             "repository_owners", "observation_cursors", "tracked_cves", "discovery_runs",
             "connector_states", "processed_events", "outbox_events"`;
}

export async function outboxTypes(prisma: PrismaClient): Promise<string[]> {
  const rows = await prisma.outboxEvent.findMany({ orderBy: { createdAt: 'asc' } });
  return rows.map((row) => row.eventType);
}

export interface FakeFile {
  readonly path: string;
  readonly sha: string;
  readonly size?: number;
}

export interface FakeRepository {
  readonly id: number;
  readonly name: string;
  readonly owner?: string;
  readonly description?: string | null;
  readonly topics?: readonly string[];
  readonly fork?: boolean;
  /** Text only the (simulated) README contains: GitHub matches it, the service never sees it. */
  readonly readme?: string;
  readonly commit?: { sha: string; treeSha: string; files: readonly FakeFile[] } | 'empty';
  /** HTTP status served for every request about this repository (deleted, DMCA, …). */
  readonly gone?: number;
  readonly extra?: Record<string, unknown>;
}

/**
 * A minimal GitHub REST API: repository search, repository metadata, head commits and trees.
 * It never serves file contents: the service has no route to ask for them.
 */
export class FakeGithub {
  private readonly repositories = new Map<number, FakeRepository>();

  constructor(private readonly mock: MockSource) {
    mock.route('/search/repositories', (request) => {
      const query = request.query.get('q') ?? '';
      const quoted = /^"([^"]+)"/.exec(query)?.[1];
      const items = [...this.repositories.values()]
        .filter((repo) => repo.gone === undefined)
        .filter((repo) =>
          quoted === undefined
            ? /CVE/i.test(this.searchable(repo))
            : this.searchable(repo).toLowerCase().includes(quoted.toLowerCase()),
        )
        .map((repo) => this.payload(repo));
      return { body: { total_count: items.length, incomplete_results: false, items } };
    });
  }

  private searchable(repo: FakeRepository): string {
    return [repo.name, repo.description ?? '', ...(repo.topics ?? []), repo.readme ?? ''].join(' ');
  }

  payload(repo: FakeRepository) {
    return githubRepo({
      id: repo.id,
      name: repo.name,
      owner: repo.owner ?? TEST_OWNER,
      description: repo.description ?? null,
      topics: [...(repo.topics ?? [])],
      fork: repo.fork ?? false,
      ...(repo.fork === true
        ? { parent: { full_name: `${TEST_OWNER}-upstream/${repo.name}` } }
        : {}),
      ...repo.extra,
    });
  }

  add(repo: FakeRepository): this {
    this.repositories.set(repo.id, repo);
    const fullName = `${repo.owner ?? TEST_OWNER}/${repo.name}`;
    const current = () => this.repositories.get(repo.id) ?? repo;
    const gone = () => {
      const status = current().gone;
      return status === undefined ? null : { status, body: { message: 'Not Found' } };
    };
    this.mock.route(
      `/repositories/${String(repo.id)}`,
      () => gone() ?? { body: this.payload(current()) },
    );
    this.mock.route(`/repos/${fullName}`, () => gone() ?? { body: this.payload(current()) });
    this.mock.route(`/repos/${fullName}/commits/main`, () => {
      const commit = current().commit;
      if (commit === undefined || commit === 'empty') {
        return { status: 409, body: { message: 'Git Repository is empty.' } };
      }
      return {
        body: {
          sha: commit.sha,
          commit: { tree: { sha: commit.treeSha }, committer: { date: '2026-10-01T00:00:00Z' } },
        },
      };
    });
    const commit = repo.commit;
    if (commit !== undefined && commit !== 'empty') this.addTree(fullName, commit);
    return this;
  }

  /** Replaces a repository (new commit, description, or `gone`). */
  update(id: number, changes: Partial<FakeRepository>): this {
    const existing = this.repositories.get(id);
    if (existing === undefined) throw new Error(`unknown repository ${String(id)}`);
    const next = { ...existing, ...changes };
    this.repositories.set(id, next);
    const commit = next.commit;
    if (commit !== undefined && commit !== 'empty') {
      this.addTree(`${next.owner ?? TEST_OWNER}/${next.name}`, commit);
    }
    return this;
  }

  private addTree(fullName: string, commit: { treeSha: string; files: readonly FakeFile[] }) {
    this.mock.route(`/repos/${fullName}/git/trees/${commit.treeSha}`, () => ({
      body: {
        sha: commit.treeSha,
        truncated: false,
        tree: commit.files.map((file) => ({
          path: file.path,
          mode: '100644',
          type: 'blob',
          sha: file.sha,
          size: file.size ?? 100,
        })),
      },
    }));
  }
}

export function integrationEnv(origin: string, overrides: Record<string, string> = {}): Env {
  return pocTestEnv({
    GITHUB_API_URL: origin,
    SOURCE_HTTP_MAX_ATTEMPTS: '1',
    POC_GITHUB_MAX_SEARCH_PAGES: '1',
    ...overrides,
  });
}

export function createEngine(
  prisma: PrismaClient,
  env: Env,
  inspections: DiscoveryJobQueue,
): DiscoveryEngine {
  const registry = createConnectorRegistry(env, {
    logger: silentLogger,
    rateLimits: {
      search: { maxRequests: 10_000, windowMs: 60_000 },
      core: { maxRequests: 10_000, windowMs: 60_000 },
    },
    retryBaseDelayMs: 1,
  });
  return new DiscoveryEngine({
    prisma,
    github: registry.github,
    inspections,
    settings: discoverySettings(env),
    logger: silentLogger,
  });
}

export function discoveryRequest(
  request: Pick<DiscoveryRequest, 'mode'> & Partial<DiscoveryRequest>,
): DiscoveryRequest {
  return {
    connector: 'github',
    trigger: 'manual',
    requestedBy: 'integration-test',
    jobId: null,
    attempt: 1,
    maxAttempts: 1,
    ...request,
  };
}

const SHA256 = 'a'.repeat(64);

/** A synthetic `intelligence.cve-observation.recorded` event listing references. */
export function observationEvent(input: {
  cveId: string;
  revision: number;
  references: readonly { url: string; tags?: readonly string[] }[];
  source?: 'nvd' | 'mitre-cve';
}): DomainEvent<CveObservationRecordedPayload> {
  const source = input.source ?? 'nvd';
  const payload = cveObservationRecordedPayloadSchema.parse({
    source,
    sourceRecordId: input.cveId,
    sourceUrl: `https://example.com/synthetic/${input.cveId}`,
    attribution: 'Synthetic integration test data',
    revision: input.revision,
    contentHash: SHA256,
    observedAt: new Date().toISOString(),
    sourceModifiedAt: null,
    runId: randomUUID(),
    cveId: input.cveId,
    change: input.revision === 1 ? 'created' : 'updated',
    content: {
      description: `Synthetic integration test record ${input.cveId}. Not a real vulnerability.`,
      source,
      references: input.references.map((reference) => ({
        url: reference.url,
        source,
        tags: [...(reference.tags ?? [])],
      })),
    },
    truncated: [],
  });
  return {
    eventId: randomUUID(),
    eventType: INTELLIGENCE_EVENT_TYPES.cveObserved,
    eventVersion: 1,
    occurredAt: new Date().toISOString(),
    producer: 'intelligence-service',
    correlationId: 'integration-test',
    payload,
  };
}

const actor = { type: 'service' as const, id: 'integration-test', username: null };

/** A synthetic `cve.record.created` (or `updated`) event. */
export function cveRecordEvent(
  cveId: string,
  facts: Partial<CveRecordCreatedPayload> & { version: number; recordId: string },
): CveRecordEvent {
  const payload: CveRecordCreatedPayload = {
    cveId,
    state: 'published',
    severity: 'unknown',
    cvssScore: null,
    cvssVersion: null,
    inKev: false,
    epssScore: null,
    epssPercentile: null,
    cweIds: [],
    publishedAt: '2026-01-01T00:00:00.000Z',
    lastModifiedAt: null,
    actor,
    ...facts,
  };
  return {
    eventId: randomUUID(),
    eventType: facts.version === 1 ? CVE_EVENT_TYPES.created : CVE_EVENT_TYPES.updated,
    eventVersion: 1,
    occurredAt: new Date().toISOString(),
    producer: 'cve-service',
    payload,
  };
}
