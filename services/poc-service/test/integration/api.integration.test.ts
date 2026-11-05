import 'reflect-metadata';

import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  apiErrorResponseSchema,
  discoveryRunSchema,
  paginationMetaSchema,
  POC_EVENT_TYPES,
  pocArtifactDetailSchema,
  pocArtifactSchema,
  pocAssociationSchema,
  pocConnectorStatusSchema,
  pocOwnerSchema,
  pocReferenceSchema,
  pocRepositorySchema,
  repositoryCommitSchema,
  verificationEventSchema,
  type Role,
} from '@cve/contracts';
import type { HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer, type TestTokenIssuer } from '@cve/testing/auth';

import { ReferenceCollector } from '../../src/events/reference-collector.js';
import { createPrismaClient, type PrismaClient } from '../../src/persistence/prisma.js';
import { scoringSettings } from '../../src/runtime.js';
import { MockSource } from '../mock-source.js';
import { FakeJobQueue, sha, silentLogger, startPocApp } from '../support.js';
import {
  createEngine,
  discoveryRequest,
  FakeGithub,
  integrationEnv,
  migrate,
  observationEvent,
  outboxTypes,
  pocDatabaseUrl,
  resetDatabase,
  syntheticCveId,
  TEST_OWNER,
} from './support.js';

// Everything here is synthetic test data (see support.ts), not real repositories or CVEs.

let prisma: PrismaClient;
let issuer: TestTokenIssuer;
let t: HttpTestApp;
let jobs: FakeJobQueue;
let viewer: Record<string, string>;
let researcher: Record<string, string>;
let admin: Record<string, string>;

const errorOf = (body: unknown) => apiErrorResponseSchema.parse(body).error;
const dataOf = <T extends z.ZodType>(schema: T, body: unknown): z.infer<T> =>
  schema.parse((body as { data: unknown }).data);
const pageOf = <T extends z.ZodType>(schema: T, body: unknown) =>
  z.object({ data: z.array(schema), meta: paginationMetaSchema }).parse(body);

async function headersFor(roles: Role[], username: string) {
  const token = await issuer.tokenFor(randomUUID(), roles, { preferred_username: username });
  return { authorization: `Bearer ${token}` };
}

const CVE = syntheticCveId(301);
const OTHER_CVE = syntheticCveId(302);

/** Discovers and inspects one synthetic repository through the real engine. */
async function seed(): Promise<{ repositoryId: string; artifactId: string }> {
  const mock = await new MockSource().start();
  try {
    const github = new FakeGithub(mock);
    github.add({
      id: 301,
      name: `${CVE}-poc`,
      description: `PoC for ${CVE}. <img src=x onerror=alert(1)> Trust me, it is safe.`,
      commit: {
        sha: sha('c301'),
        treeSha: sha('t301'),
        files: [
          { path: 'exploit.py', sha: sha('e') },
          { path: 'payload.exe', sha: sha('x') },
          { path: 'docs.docm', sha: sha('d') },
        ],
      },
    });
    const queue = new FakeJobQueue();
    const engine = createEngine(prisma, integrationEnv(mock.origin), queue);
    const signal = new AbortController().signal;
    await engine.run(discoveryRequest({ mode: 'cve', cveId: CVE }), signal);
    for (const { repositoryId } of queue.inspections) {
      await engine.run(discoveryRequest({ mode: 'repository', repositoryId }), signal);
    }
  } finally {
    await mock.stop();
  }
  const repository = await prisma.pocRepository.findFirstOrThrow();
  const artifact = await prisma.pocArtifact.findFirstOrThrow();
  return { repositoryId: repository.id, artifactId: artifact.id };
}

beforeAll(async () => {
  const url = pocDatabaseUrl();
  migrate(url);
  prisma = createPrismaClient(url);
  issuer = await createTestTokenIssuer();
  jobs = new FakeJobQueue();
  t = await startPocApp(issuer, { prisma, jobs });
  viewer = await headersFor(['viewer'], 'zz-test-viewer');
  researcher = await headersFor(['vulnerability-researcher'], 'zz-test-researcher');
  admin = await headersFor(['administrator'], 'zz-test-admin');
});

afterAll(async () => {
  await t.close();
  await resetDatabase(prisma);
  await prisma.$disconnect();
});

let ids: { repositoryId: string; artifactId: string };

beforeEach(async () => {
  await resetDatabase(prisma);
  jobs.discovery.splice(0);
  ids = await seed();
});

describe('read API', () => {
  it('lists repositories, owners, commits and artifacts with their metadata', async () => {
    const repos = pageOf(
      pocRepositorySchema,
      (await t.http.get(`/api/v1/poc-repositories?cveId=${CVE}`).set(viewer).expect(200)).body,
    );
    expect(repos.meta.totalItems).toBe(1);
    const repo = repos.data[0];
    expect(repo).toMatchObject({
      fullName: `${TEST_OWNER}/${CVE}-poc`,
      url: `https://github.com/${TEST_OWNER}/${CVE}-poc`,
      cveIds: [CVE],
      latestCommit: { sha: sha('c301'), treeSha: sha('t301') },
      discoveredBy: 'github',
    });
    // Untrusted text is stored as plain text (sanitised of control characters, never rendered).
    expect(repo?.description).toContain('Trust me');

    const owners = pageOf(
      pocOwnerSchema,
      (await t.http.get('/api/v1/poc-owners').set(viewer).expect(200)).body,
    );
    expect(owners.data).toEqual([
      expect.objectContaining({ login: TEST_OWNER, repositoryCount: 1, type: 'user' }),
    ]);

    const commits = pageOf(
      repositoryCommitSchema,
      (
        await t.http
          .get(`/api/v1/poc-repositories/${ids.repositoryId}/commits`)
          .set(viewer)
          .expect(200)
      ).body,
    );
    expect(commits.data.map((commit) => commit.sha)).toEqual([sha('c301')]);

    const detail = dataOf(
      pocArtifactDetailSchema,
      (await t.http.get(`/api/v1/poc-artifacts/${ids.artifactId}`).set(viewer).expect(200)).body,
    );
    expect(detail.riskIndicators).toEqual(
      expect.arrayContaining(['contains-executables', 'contains-macro-documents']),
    );
    expect(detail.files.map((entry) => entry.category).sort()).toEqual([
      'executable',
      'macro-document',
      'source',
    ]);
    expect(detail.verificationStatus).toBe('unverified');
  });

  it('lists connectors with their approval, origin and last run', async () => {
    const res = await t.http.get('/api/v1/poc-connectors').set(viewer).expect(200);
    const connectors = z
      .array(pocConnectorStatusSchema)
      .parse((res.body as { data: unknown }).data);
    expect(connectors.map((entry) => [entry.connector, entry.approved])).toEqual([
      ['github', true],
      ['cve-references', true],
    ]);
    expect(connectors[0]?.lastRunStatus).toBe('succeeded');

    const runs = pageOf(
      discoveryRunSchema,
      (await t.http.get('/api/v1/poc-discovery-runs?mode=cve').set(viewer).expect(200)).body,
    );
    expect(runs.data).toEqual([expect.objectContaining({ cveId: CVE, status: 'succeeded' })]);
  });

  it('returns 404 for unknown resources', async () => {
    const missing = randomUUID();
    await t.http.get(`/api/v1/poc-repositories/${missing}`).set(viewer).expect(404);
    await t.http.get(`/api/v1/poc-artifacts/${missing}`).set(viewer).expect(404);
    await t.http.get(`/api/v1/poc-associations/${missing}`).set(viewer).expect(404);
  });
});

describe('association review', () => {
  it('reviews an association with optimistic concurrency', async () => {
    const list = pageOf(
      pocAssociationSchema,
      (await t.http.get(`/api/v1/poc-associations?cveId=${CVE}`).set(viewer).expect(200)).body,
    );
    const association = list.data[0];
    expect(association).toMatchObject({ reviewStatus: 'candidate', origin: 'discovered' });
    if (association === undefined) return;

    const fetched = await t.http
      .get(`/api/v1/poc-associations/${association.id}`)
      .set(viewer)
      .expect(200);
    const tag = fetched.headers['etag'];
    expect(tag).toBe(`"${String(association.version)}"`);

    const reviewed = await t.http
      .patch(`/api/v1/poc-associations/${association.id}`)
      .set(researcher)
      .set('if-match', String(tag))
      .send({ reviewStatus: 'confirmed', note: 'Checked the file listing manually.' })
      .expect(200);
    expect(dataOf(pocAssociationSchema, reviewed.body)).toMatchObject({
      reviewStatus: 'confirmed',
      reviewedBy: 'zz-test-researcher',
      version: association.version + 1,
    });

    // The stale ETag is refused.
    const stale = await t.http
      .patch(`/api/v1/poc-associations/${association.id}`)
      .set(researcher)
      .set('if-match', String(tag))
      .send({ reviewStatus: 'rejected' })
      .expect(412);
    expect(errorOf(stale.body).details?.[0]?.path).toBe('If-Match');
    expect(await outboxTypes(prisma)).toContain(POC_EVENT_TYPES.associationReviewed);
  });

  it('keeps a confirmed review when the repository is rescored', async () => {
    const association = await prisma.pocAssociation.findFirstOrThrow({ where: { cveId: CVE } });
    await t.http
      .patch(`/api/v1/poc-associations/${association.id}`)
      .set(researcher)
      .send({ reviewStatus: 'rejected', note: null })
      .expect(200);
    // A reference to the same repository arrives: it is rescored, the review stays.
    const collector = new ReferenceCollector(
      prisma,
      jobs,
      scoringSettings(integrationEnv('http://github.test')),
      silentLogger,
    );
    await collector.apply(
      observationEvent({
        cveId: CVE,
        revision: 1,
        references: [{ url: `https://github.com/${TEST_OWNER}/${CVE}-poc`, tags: ['Exploit'] }],
      }),
    );
    const after = await prisma.pocAssociation.findUniqueOrThrow({ where: { id: association.id } });
    expect(after.reviewStatus).toBe('rejected');
    const references = pageOf(
      pocReferenceSchema,
      (await t.http.get(`/api/v1/poc-references?cveId=${CVE}`).set(viewer).expect(200)).body,
    );
    expect(references.data).toEqual([
      expect.objectContaining({ kind: 'github-repository', repositoryId: ids.repositoryId }),
    ]);
  });

  it('creates a manual association once', async () => {
    const created = await t.http
      .post('/api/v1/poc-associations')
      .set(researcher)
      .send({ repositoryId: ids.repositoryId, cveId: OTHER_CVE, note: 'Same bug class' })
      .expect(201);
    const association = dataOf(pocAssociationSchema, created.body);
    expect(association).toMatchObject({
      cveId: OTHER_CVE,
      origin: 'manual',
      reviewStatus: 'confirmed',
      reviewedBy: 'zz-test-researcher',
    });
    expect(created.headers['location']).toBe(`/api/v1/poc-associations/${association.id}`);
    await t.http
      .post('/api/v1/poc-associations')
      .set(researcher)
      .send({ repositoryId: ids.repositoryId, cveId: OTHER_CVE })
      .expect(409);
    await t.http
      .post('/api/v1/poc-associations')
      .set(researcher)
      .send({ repositoryId: randomUUID(), cveId: OTHER_CVE })
      .expect(404);
  });
});

describe('artifact verification', () => {
  const verify = (headers: Record<string, string>, status: string, ifMatch?: string) => {
    const request = t.http
      .post(`/api/v1/poc-artifacts/${ids.artifactId}/verification`)
      .set(headers);
    if (ifMatch !== undefined) request.set('if-match', ifMatch);
    return request.send({ status, reason: `Synthetic test decision: ${status}` });
  };

  it('records transitions in an append-only history', async () => {
    const res = await verify(researcher, 'in-review', '"1"').expect(200);
    expect(dataOf(pocArtifactSchema, res.body)).toMatchObject({
      verificationStatus: 'in-review',
      verificationUpdatedBy: 'zz-test-researcher',
      version: 2,
    });
    await verify(researcher, 'in-review').expect(409);
    await verify(researcher, 'verified', '"1"').expect(412);
    await verify(researcher, 'verified', '"2"').expect(200);

    const history = z
      .array(verificationEventSchema)
      .parse(
        (
          (
            await t.http
              .get(`/api/v1/poc-artifacts/${ids.artifactId}/verification-history`)
              .set(viewer)
              .expect(200)
          ).body as { data: unknown }
        ).data,
      );
    // Newest first.
    expect(history.map((entry) => [entry.fromStatus, entry.toStatus])).toEqual([
      ['in-review', 'verified'],
      ['unverified', 'in-review'],
    ]);
    await expect(
      prisma.$executeRaw`UPDATE "artifact_verification_events" SET "reason" = 'edited'`,
    ).rejects.toThrow(/append-only/);
  });

  it('hides malicious artifacts from users without quarantine:read', async () => {
    await verify(researcher, 'malicious').expect(200);

    // Viewers no longer see the artifact anywhere.
    await t.http.get(`/api/v1/poc-artifacts/${ids.artifactId}`).set(viewer).expect(404);
    const list = pageOf(
      pocArtifactSchema,
      (await t.http.get('/api/v1/poc-artifacts').set(viewer).expect(200)).body,
    );
    expect(list.data).toHaveLength(0);
    await t.http
      .get(`/api/v1/poc-artifacts/${ids.artifactId}/verification-history`)
      .set(viewer)
      .expect(404);
    const filtered = pageOf(
      pocArtifactSchema,
      (
        await t.http
          .get('/api/v1/poc-artifacts?verificationStatus=malicious')
          .set(viewer)
          .expect(200)
      ).body,
    );
    expect(filtered.data).toHaveLength(0);

    // Researchers (quarantine:read) still see it, but cannot release it.
    await t.http.get(`/api/v1/poc-artifacts/${ids.artifactId}`).set(researcher).expect(200);
    const forbidden = await verify(researcher, 'in-review').expect(403);
    expect(errorOf(forbidden.body).message).toMatch(/quarantine:manage/);
    // Administrators (quarantine:manage) can move it back to review.
    await verify(admin, 'in-review').expect(200);
    await t.http.get(`/api/v1/poc-artifacts/${ids.artifactId}`).set(viewer).expect(200);
    expect(await outboxTypes(prisma)).toContain(POC_EVENT_TYPES.artifactVerificationChanged);
  });
});

describe('discovery jobs', () => {
  it('queues repository inspection for a known repository only', async () => {
    const res = await t.http
      .post('/api/v1/poc-discovery-runs')
      .set(researcher)
      .send({ mode: 'repository', connector: 'github', repositoryId: ids.repositoryId })
      .expect(202);
    expect((res.body as { data: { queued: boolean } }).data.queued).toBe(true);
    expect(jobs.discovery.at(-1)?.payload).toMatchObject({
      mode: 'repository',
      repositoryId: ids.repositoryId,
      requestedBy: 'zz-test-researcher',
    });
    await t.http
      .post('/api/v1/poc-discovery-runs')
      .set(researcher)
      .send({ mode: 'repository', connector: 'github', repositoryId: randomUUID() })
      .expect(404);
  });
});
