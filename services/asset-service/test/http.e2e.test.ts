import 'reflect-metadata';

import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { apiErrorResponseSchema, type Role } from '@cve/contracts';
import type { HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer, type TestTokenIssuer } from '@cve/testing/auth';

import { startAssetApp } from './support.js';

// These tests stop at authentication, authorization or validation, before any database access
// (the app is wired to an unreachable database). Persistence is covered by the integration suite.

let issuer: TestTokenIssuer;
let t: HttpTestApp;
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
  t = await startAssetApp(issuer);
  viewer = await headersFor(['viewer']);
  analyst = await headersFor(['security-analyst']);
  researcher = await headersFor(['vulnerability-researcher']);
});

afterAll(async () => {
  await t.close();
});

const READ_ROUTES = [
  '/api/v1/vendors',
  `/api/v1/vendors/${ID}`,
  `/api/v1/vendors/${ID}/products`,
  `/api/v1/vendors/${ID}/analytics`,
  '/api/v1/products',
  `/api/v1/products/${ID}`,
  `/api/v1/products/${ID}/vulnerabilities`,
  `/api/v1/products/${ID}/vulnerability-history`,
  '/api/v1/cve-associations',
] as const;

const WRITE_ROUTES = [
  ['post', '/api/v1/vendors'],
  ['patch', `/api/v1/vendors/${ID}`],
  ['delete', `/api/v1/vendors/${ID}`],
  ['post', '/api/v1/products'],
  ['patch', `/api/v1/products/${ID}`],
  ['delete', `/api/v1/products/${ID}`],
  ['post', `/api/v1/products/${ID}/cpes`],
  ['delete', `/api/v1/products/${ID}/cpes/${ID}`],
  ['post', `/api/v1/products/${ID}/identifiers`],
  ['delete', `/api/v1/products/${ID}/identifiers/${ID}`],
  ['put', `/api/v1/products/${ID}/vulnerabilities/CVE-2026-90001`],
  ['delete', `/api/v1/products/${ID}/vulnerabilities/CVE-2026-90001`],
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
    await t.http.get('/api/v1/vendors').set('authorization', `Bearer ${token}`).expect(401);
  });
});

describe('authorization', () => {
  it.each(WRITE_ROUTES)('%s %s needs asset:manage (viewer → 403)', async (method, path) => {
    const res = await t.http[method](path).set(viewer).send({}).expect(403);
    expect(errorOf(res.body).code).toBe('FORBIDDEN');
  });

  it('vulnerability researchers can read but not manage assets', async () => {
    await t.http.post('/api/v1/vendors').set(researcher).send({ name: 'x' }).expect(403);
  });

  it('a token without any role cannot read', async () => {
    const none = await headersFor([]);
    await t.http.get('/api/v1/vendors').set(none).expect(403);
  });
});

describe('validation (security analysts hold asset:manage)', () => {
  it.each([
    ['get', '/api/v1/vendors/not-a-uuid', 'vendorId'],
    ['get', '/api/v1/products/123', 'productId'],
    ['get', '/api/v1/products/123/vulnerabilities', 'productId'],
    ['delete', `/api/v1/products/${ID}/cpes/nope`, 'cpeId'],
  ] as const)('%s %s rejects a malformed ID', async (method, path, field) => {
    const res = await t.http[method](path).set(analyst).expect(400);
    expect(errorOf(res.body).details?.map((d) => d.path)).toContain(field);
  });

  it.each([
    ['/api/v1/vendors?pageSize=1000', 'pageSize'],
    ['/api/v1/vendors?sort=popularity', 'sort'],
    ['/api/v1/vendors?unknown=1', ''],
    ['/api/v1/products?cpe=cpe:2.3:a:only:three', 'cpe'],
    ['/api/v1/products?type=firmware', 'type'],
    ['/api/v1/products?vendor=Not%20A%20Slug!', 'vendor'],
    [`/api/v1/products/${ID}/vulnerabilities?severity=urgent`, 'severity.0'],
    [`/api/v1/products/${ID}/vulnerabilities?includeWithdrawn=yes`, 'includeWithdrawn'],
    [`/api/v1/products/${ID}/vulnerabilities?version=1.0%201`, 'version'],
    [`/api/v1/products/${ID}/vulnerability-history?change=deleted`, 'change'],
    ['/api/v1/cve-associations?cveId=CVE-26-1', 'cveId'],
    [`/api/v1/vendors/${ID}/analytics?topProducts=500`, 'topProducts'],
    [`/api/v1/vendors/${ID}/products?vendorId=${ID}`, ''],
  ])('GET %s is rejected', async (path, field) => {
    const res = await t.http.get(path).set(analyst).expect(400);
    expect(errorOf(res.body).details?.map((d) => d.path)).toContain(field);
  });

  it.each([
    [{}, 'name'],
    [{ name: 'Acme', unexpected: true }, ''],
    [{ name: 'Acme', slug: 'Has Spaces' }, 'slug'],
    [{ name: 'Acme', website: 'ftp://example.com' }, 'website'],
    [{ name: 'Acme', website: 'https://user:pw@example.com' }, 'website'],
    [{ name: 'Acme\u0007' }, 'name'],
  ])('POST /vendors rejects %j', async (body, field) => {
    const res = await t.http.post('/api/v1/vendors').set(analyst).send(body).expect(400);
    expect(errorOf(res.body).details?.map((d) => d.path)).toContain(field);
  });

  it('PATCH /vendors needs at least one field', async () => {
    await t.http.patch(`/api/v1/vendors/${ID}`).set(analyst).send({}).expect(400);
  });

  it('PATCH /vendors rejects slug changes (slugs are immutable)', async () => {
    const res = await t.http
      .patch(`/api/v1/vendors/${ID}`)
      .set(analyst)
      .send({ slug: 'new' })
      .expect(400);
    expect(errorOf(res.body).message).toBe('Request validation failed');
  });

  it.each(['W/"1"', '"0"', 'abc'])('rejects If-Match %s', async (header) => {
    const res = await t.http
      .patch(`/api/v1/vendors/${ID}`)
      .set(analyst)
      .set('if-match', header)
      .send({ name: 'Acme' })
      .expect(400);
    expect(errorOf(res.body).details?.[0]?.path).toBe('If-Match');
  });

  it.each([
    [{ vendorId: 'x', name: 'Widget' }, 'vendorId'],
    [{ vendorId: ID, name: 'Widget', type: 'firmware' }, 'type'],
    [{ vendorId: ID, name: 'Widget', cpes: [{ cpe: 'cpe:/a:acme:widget' }] }, 'cpes.0.cpe'],
    [
      { vendorId: ID, name: 'Widget', identifiers: [{ type: 'purl', value: 'npm/widget' }] },
      'identifiers.0.value',
    ],
    [
      { vendorId: ID, name: 'Widget', identifiers: [{ type: 'serial', value: 'x' }] },
      'identifiers.0.type',
    ],
  ])('POST /products rejects %j', async (body, field) => {
    const res = await t.http.post('/api/v1/products').set(analyst).send(body).expect(400);
    expect(errorOf(res.body).details?.map((d) => d.path)).toContain(field);
  });

  it.each([
    [{ ranges: [] }, 'ranges'],
    [{ ranges: [{ version: '1.0', versionEndExcluding: '2.0' }] }, 'ranges.0.version'],
    [
      { ranges: [{ versionStartIncluding: '1.0', versionStartExcluding: '1.0' }] },
      'ranges.0.versionStartExcluding',
    ],
    [{ ranges: [{ status: 'patched' }] }, 'ranges.0.status'],
    [{ ranges: [{ version: '1.0' }, { version: '1.0' }] }, 'ranges.1'],
  ])('PUT /products/:id/vulnerabilities/:cveId rejects %j', async (body, field) => {
    const res = await t.http
      .put(`/api/v1/products/${ID}/vulnerabilities/CVE-2026-90001`)
      .set(analyst)
      .send(body)
      .expect(400);
    expect(errorOf(res.body).details?.map((d) => d.path)).toContain(field);
  });

  it('PUT /products/:id/vulnerabilities/:cveId rejects an invalid CVE ID', async () => {
    await t.http
      .put(`/api/v1/products/${ID}/vulnerabilities/CVE-1998-0001`)
      .set(analyst)
      .send({ ranges: [{ version: '1.0' }] })
      .expect(400);
  });
});
