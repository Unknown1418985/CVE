import 'reflect-metadata';

import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { apiErrorResponseSchema, downloadSourceStatusSchema, type Role } from '@cve/contracts';
import type { HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer, type TestTokenIssuer } from '@cve/testing/auth';

import { startDownloadApp } from './support.js';

// These tests stop at authentication, authorization or validation, before any database access
// (the app is wired to an unreachable database). Persistence is covered by the integration suite.

let issuer: TestTokenIssuer;
let t: HttpTestApp;
const headers: Partial<Record<Role | 'none', Record<string, string>>> = {};
const ID = '00000000-0000-4000-8000-000000000001';
const SHA = 'b'.repeat(40);
const errorOf = (body: unknown) => apiErrorResponseSchema.parse(body).error;
const as = (role: Role | 'none') => headers[role] ?? {};

beforeAll(async () => {
  issuer = await createTestTokenIssuer();
  t = await startDownloadApp(issuer);
  for (const role of [
    'viewer',
    'security-analyst',
    'vulnerability-researcher',
    'administrator',
  ] as const) {
    headers[role] = { authorization: `Bearer ${await issuer.tokenFor(randomUUID(), [role])}` };
  }
  headers.none = { authorization: `Bearer ${await issuer.tokenFor(randomUUID(), [])}` };
});

afterAll(async () => {
  await t.close();
});

const READ_ROUTES = [
  '/api/v1/download-sources',
  '/api/v1/download-requests',
  `/api/v1/download-requests/${ID}`,
  '/api/v1/download-artifacts',
  `/api/v1/download-artifacts/${ID}`,
  `/api/v1/download-artifacts/${ID}/lifecycle-history`,
  `/api/v1/download-artifacts/${ID}/scans`,
  `/api/v1/download-artifacts/${ID}/content`,
] as const;

const WRITE_ROUTES = [
  ['post', '/api/v1/download-requests'],
  ['post', `/api/v1/download-requests/${ID}/retry`],
  ['post', `/api/v1/download-requests/${ID}/cancel`],
  ['post', `/api/v1/download-artifacts/${ID}/rescan`],
  ['post', `/api/v1/download-artifacts/${ID}/lifecycle`],
] as const;

describe('authentication', () => {
  it.each(READ_ROUTES)('GET %s requires a bearer token', async (path) => {
    const res = await t.http.get(path).expect(401);
    expect(errorOf(res.body).code).toBe('UNAUTHORIZED');
  });

  it.each(WRITE_ROUTES)('%s %s requires a bearer token', async (method, path) => {
    await t.http[method](path).send({}).expect(401);
  });
});

describe('authorization', () => {
  it.each(READ_ROUTES)('viewers cannot read %s (no download:read)', async (path) => {
    await t.http.get(path).set(as('viewer')).expect(403);
  });

  it('a token without roles cannot read', async () => {
    await t.http.get('/api/v1/download-sources').set(as('none')).expect(403);
  });

  it('security analysts read requests but cannot schedule, inspect or manage quarantine', async () => {
    await t.http.get('/api/v1/download-sources').set(as('security-analyst')).expect(200);
    await t.http.post('/api/v1/download-requests').set(as('security-analyst')).send({}).expect(403);
    await t.http
      .get(`/api/v1/download-artifacts/${ID}/scans`)
      .set(as('security-analyst'))
      .expect(403);
    await t.http
      .post(`/api/v1/download-artifacts/${ID}/lifecycle`)
      .set(as('security-analyst'))
      .send({ status: 'released', reason: 'x' })
      .expect(403);
  });

  it('vulnerability researchers schedule downloads but cannot release, reject or rescan', async () => {
    for (const path of [
      `/api/v1/download-artifacts/${ID}/lifecycle`,
      `/api/v1/download-artifacts/${ID}/rescan`,
    ]) {
      const res = await t.http
        .post(path)
        .set(as('vulnerability-researcher'))
        .send({ status: 'released', reason: 'looks fine' })
        .expect(403);
      expect(errorOf(res.body).code).toBe('FORBIDDEN');
    }
  });
});

describe('sources', () => {
  it('lists approved sources with their allowlists and limits', async () => {
    const res = await t.http
      .get('/api/v1/download-sources')
      .set(as('security-analyst'))
      .expect(200);
    const sources = (res.body as { data: unknown[] }).data.map((item) =>
      downloadSourceStatusSchema.parse(item),
    );
    expect(sources.map((source) => [source.source, source.enabled])).toEqual([
      ['github-archive', true],
      ['exploit-db', false],
    ]);
    expect(sources[0]?.allowedHosts).toEqual(['codeload.github.com']);
  });
});

describe('validation', () => {
  it.each([
    [{}, 'url'],
    [{ url: `https://github.com/zz-test/poc/commit/${SHA}`, pocArtifactId: ID }, 'url'],
    [{ pocArtifactId: 'x' }, 'pocArtifactId'],
    [{ url: `https://github.com/zz-test/poc/commit/${SHA}`, priority: 0 }, 'priority'],
    [{ url: `https://github.com/zz-test/poc/commit/${SHA}`, cveIds: ['CVE-1'] }, 'cveIds.0'],
    [
      { url: `https://github.com/zz-test/poc/commit/${SHA}`, scheduledFor: 'tomorrow' },
      'scheduledFor',
    ],
    [{ url: `https://github.com/zz-test/poc/commit/${SHA}`, extra: true }, ''],
  ])('POST /download-requests rejects %j', async (body, field) => {
    const res = await t.http
      .post('/api/v1/download-requests')
      .set(as('vulnerability-researcher'))
      .send(body)
      .expect(400);
    expect(errorOf(res.body).details?.map((detail) => detail.path)).toContain(field);
  });

  it.each([
    'https://evil.test/payload.tar.gz',
    'http://github.com/zz-test/poc/commit/' + SHA,
    'https://github.com/zz-test/poc/archive/refs/heads/main.tar.gz',
    'https://127.0.0.1/x',
    'https://169.254.169.254/latest/meta-data',
    'file:///etc/passwd',
    'https://www.exploit-db.com/exploits/1234',
  ])('refuses %s: not an enabled source (422, nothing is fetched)', async (url) => {
    const res = await t.http
      .post('/api/v1/download-requests')
      .set(as('vulnerability-researcher'))
      .send({ url })
      .expect(422);
    expect(errorOf(res.body).details?.[0]?.path).toBe('url');
  });

  it.each([
    ['/api/v1/download-requests?status=done', 'status.0'],
    ['/api/v1/download-requests?source=pastebin', 'source'],
    ['/api/v1/download-requests?pageSize=500', 'pageSize'],
    ['/api/v1/download-artifacts?scanStatus=safe', 'scanStatus.0'],
    ['/api/v1/download-artifacts?sha256=abc', 'sha256'],
    ['/api/v1/download-artifacts?unknown=1', ''],
    [`/api/v1/download-requests/not-a-uuid`, 'requestId'],
    [`/api/v1/download-artifacts/not-a-uuid`, 'artifactId'],
  ])('GET %s is rejected', async (path, field) => {
    const res = await t.http.get(path).set(as('administrator')).expect(400);
    expect(errorOf(res.body).details?.map((detail) => detail.path)).toContain(field);
  });

  it.each([
    [{ status: 'released' }, 'reason'],
    [{ status: 'verified', reason: 'x' }, 'status'],
    [{ status: 'released', reason: 'ok\u0007' }, 'reason'],
  ])('POST /download-artifacts/:id/lifecycle rejects %j', async (body, field) => {
    const res = await t.http
      .post(`/api/v1/download-artifacts/${ID}/lifecycle`)
      .set(as('administrator'))
      .send(body)
      .expect(400);
    expect(errorOf(res.body).details?.map((detail) => detail.path)).toContain(field);
  });

  it('rejects a malformed If-Match', async () => {
    const res = await t.http
      .post(`/api/v1/download-artifacts/${ID}/lifecycle`)
      .set(as('administrator'))
      .set('if-match', 'W/"1"')
      .send({ status: 'released', reason: 'reviewed' })
      .expect(400);
    expect(errorOf(res.body).details?.[0]?.path).toBe('If-Match');
  });
});
