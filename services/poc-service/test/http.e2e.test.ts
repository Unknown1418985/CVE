import 'reflect-metadata';

import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { apiErrorResponseSchema, type Role } from '@cve/contracts';
import type { HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer, type TestTokenIssuer } from '@cve/testing/auth';

import { FakeJobQueue, startPocApp } from './support.js';

// These tests stop at authentication, authorization or validation, before any database access
// (the app is wired to an unreachable database). Persistence is covered by the integration suite.
// The one exception is queuing a CVE discovery, which only talks to the (fake) job queue.

let issuer: TestTokenIssuer;
let t: HttpTestApp;
let jobs: FakeJobQueue;
let viewer: Record<string, string>;
let analyst: Record<string, string>;
let researcher: Record<string, string>;

const ID = '00000000-0000-4000-8000-000000000001';
const errorOf = (body: unknown) => apiErrorResponseSchema.parse(body).error;

async function headersFor(roles: Role[]) {
  return { authorization: `Bearer ${await issuer.tokenFor(randomUUID(), roles)}` };
}

beforeAll(async () => {
  issuer = await createTestTokenIssuer();
  jobs = new FakeJobQueue();
  t = await startPocApp(issuer, { jobs });
  viewer = await headersFor(['viewer']);
  analyst = await headersFor(['security-analyst']);
  researcher = await headersFor(['vulnerability-researcher']);
});

afterAll(async () => {
  await t.close();
});

const READ_ROUTES = [
  '/api/v1/poc-repositories',
  `/api/v1/poc-repositories/${ID}`,
  `/api/v1/poc-repositories/${ID}/commits`,
  '/api/v1/poc-owners',
  `/api/v1/poc-owners/${ID}`,
  '/api/v1/poc-associations',
  `/api/v1/poc-associations/${ID}`,
  '/api/v1/poc-artifacts',
  `/api/v1/poc-artifacts/${ID}`,
  `/api/v1/poc-artifacts/${ID}/verification-history`,
  '/api/v1/poc-references',
  '/api/v1/poc-connectors',
  '/api/v1/poc-discovery-runs',
  `/api/v1/poc-discovery-runs/${ID}`,
] as const;

const WRITE_ROUTES = [
  ['post', '/api/v1/poc-associations'],
  ['patch', `/api/v1/poc-associations/${ID}`],
  ['post', `/api/v1/poc-artifacts/${ID}/verification`],
  ['post', '/api/v1/poc-discovery-runs'],
] as const;

describe('authentication', () => {
  it.each(READ_ROUTES)('GET %s requires a bearer token', async (path) => {
    const res = await t.http.get(path).expect(401);
    expect(errorOf(res.body).code).toBe('UNAUTHORIZED');
  });

  it.each(WRITE_ROUTES)('%s %s requires a bearer token', async (method, path) => {
    await t.http[method](path).expect(401);
  });

  it('rejects a token from another issuer', async () => {
    const other = await createTestTokenIssuer();
    const token = await other.tokenFor(randomUUID(), ['administrator']);
    await t.http
      .get('/api/v1/poc-repositories')
      .set('authorization', `Bearer ${token}`)
      .expect(401);
  });
});

describe('authorization', () => {
  it.each(WRITE_ROUTES)('%s %s needs poc:manage (viewer → 403)', async (method, path) => {
    const res = await t.http[method](path).set(viewer).send({}).expect(403);
    expect(errorOf(res.body).code).toBe('FORBIDDEN');
  });

  it.each(WRITE_ROUTES)('%s %s needs poc:manage (security analyst → 403)', async (method, path) => {
    await t.http[method](path).set(analyst).send({}).expect(403);
  });

  it('a token without any role cannot read', async () => {
    const none = await headersFor([]);
    await t.http.get('/api/v1/poc-repositories').set(none).expect(403);
  });

  it('viewers and analysts pass authorization on reads (validation answers first)', async () => {
    await t.http.get('/api/v1/poc-repositories?pageSize=1000').set(viewer).expect(400);
    await t.http.get('/api/v1/poc-artifacts?pageSize=1000').set(analyst).expect(400);
  });
});

describe('validation (vulnerability researchers hold poc:manage)', () => {
  it.each([
    ['get', `/api/v1/poc-repositories/not-a-uuid`, 'repositoryId'],
    ['get', `/api/v1/poc-owners/123`, 'ownerId'],
    ['get', `/api/v1/poc-associations/x`, 'associationId'],
    ['get', `/api/v1/poc-artifacts/x/verification-history`, 'artifactId'],
    ['get', `/api/v1/poc-discovery-runs/x`, 'runId'],
  ] as const)('%s %s rejects a malformed ID', async (method, path, field) => {
    const res = await t.http[method](path).set(researcher).expect(400);
    expect(errorOf(res.body).details?.map((d) => d.path)).toContain(field);
  });

  it.each([
    ['/api/v1/poc-repositories?pageSize=1000', 'pageSize'],
    ['/api/v1/poc-repositories?sort=popularity', 'sort'],
    ['/api/v1/poc-repositories?unknown=1', ''],
    ['/api/v1/poc-repositories?cveId=CVE-26-1', 'cveId'],
    ['/api/v1/poc-repositories?minConfidence=2', 'minConfidence'],
    ['/api/v1/poc-associations?reviewStatus=maybe', 'reviewStatus.0'],
    ['/api/v1/poc-artifacts?verificationStatus=safe', 'verificationStatus.0'],
    ['/api/v1/poc-artifacts?fingerprint=abc', 'fingerprint'],
    ['/api/v1/poc-references?kind=torrent', 'kind.0'],
    ['/api/v1/poc-discovery-runs?connector=exploit-db', 'connector'],
  ])('GET %s is rejected', async (path, field) => {
    const res = await t.http.get(path).set(researcher).expect(400);
    expect(errorOf(res.body).details?.map((d) => d.path)).toContain(field);
  });

  it.each([
    [{}, 'reviewStatus'],
    [{ reviewStatus: 'trusted' }, 'reviewStatus'],
    [{ reviewStatus: 'confirmed', extra: 1 }, ''],
  ])('PATCH /poc-associations/:id rejects %j', async (body, field) => {
    const res = await t.http
      .patch(`/api/v1/poc-associations/${ID}`)
      .set(researcher)
      .send(body)
      .expect(400);
    expect(errorOf(res.body).details?.map((d) => d.path)).toContain(field);
  });

  it.each(['W/"1"', '"0"', 'abc'])('rejects If-Match %s', async (header) => {
    const res = await t.http
      .patch(`/api/v1/poc-associations/${ID}`)
      .set(researcher)
      .set('if-match', header)
      .send({ reviewStatus: 'confirmed' })
      .expect(400);
    expect(errorOf(res.body).details?.[0]?.path).toBe('If-Match');
  });

  it.each([
    [{ repositoryId: 'x', cveId: 'CVE-2026-900001' }, 'repositoryId'],
    [{ repositoryId: ID, cveId: 'CVE-1998-0001' }, 'cveId'],
  ])('POST /poc-associations rejects %j', async (body, field) => {
    const res = await t.http
      .post('/api/v1/poc-associations')
      .set(researcher)
      .send(body)
      .expect(400);
    expect(errorOf(res.body).details?.map((d) => d.path)).toContain(field);
  });

  it.each([
    [{ status: 'verified' }, 'reason'],
    [{ status: 'safe', reason: 'x' }, 'status'],
    [{ status: 'verified', reason: 'ok\u0007' }, 'reason'],
  ])('POST /poc-artifacts/:id/verification rejects %j', async (body, field) => {
    const res = await t.http
      .post(`/api/v1/poc-artifacts/${ID}/verification`)
      .set(researcher)
      .send(body)
      .expect(400);
    expect(errorOf(res.body).details?.map((d) => d.path)).toContain(field);
  });

  it.each([
    [{ mode: 'cve', connector: 'github' }, 'cveId'],
    [{ mode: 'cve', connector: 'exploit-db', cveId: 'CVE-2026-900001' }, 'connector'],
    [{ mode: 'clone', connector: 'github' }, 'mode'],
    [{ mode: 'repository', connector: 'github', repositoryId: 'x' }, 'repositoryId'],
  ])('POST /poc-discovery-runs rejects %j', async (body, field) => {
    const res = await t.http
      .post('/api/v1/poc-discovery-runs')
      .set(researcher)
      .send(body)
      .expect(400);
    expect(errorOf(res.body).details?.map((d) => d.path)).toContain(field);
  });

  it('rejects a malformed idempotency key', async () => {
    await t.http
      .post('/api/v1/poc-discovery-runs')
      .set(researcher)
      .set('idempotency-key', 'has spaces')
      .send({ mode: 'cve', connector: 'github', cveId: 'CVE-2026-900001' })
      .expect(400);
  });
});

describe('POST /poc-discovery-runs', () => {
  it('queues a CVE discovery once per idempotency key', async () => {
    const send = () =>
      t.http
        .post('/api/v1/poc-discovery-runs')
        .set(researcher)
        .set('idempotency-key', 'same-key')
        .send({ mode: 'cve', connector: 'github', cveId: 'CVE-2026-900001' })
        .expect(202);
    const first = (await send()).body as { data: { jobId: string; queued: boolean } };
    const second = (await send()).body as { data: { jobId: string; queued: boolean } };
    expect(first.data.queued).toBe(true);
    expect(second.data).toEqual({ jobId: first.data.jobId, queued: false });
    expect(jobs.discovery).toHaveLength(1);
    expect(jobs.discovery[0]?.payload).toMatchObject({
      mode: 'cve',
      cveId: 'CVE-2026-900001',
      trigger: 'manual',
    });
  });
});
