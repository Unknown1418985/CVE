import 'reflect-metadata';

import { randomUUID } from 'node:crypto';

import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import { createTokenVerifier, IntrospectionSessionChecker } from '@cve/auth';
import { createLogger } from '@cve/logger';
import { configureServiceApp } from '@cve/shared';
import { createHttpTestApp, type HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer, type TestTokenIssuer } from '@cve/testing/auth';

import { AppModule } from '../src/app.module.js';
import { loadGatewayEnv } from '../src/config/env.js';
import type { HttpFetch } from '../src/services-health/services-health.constants.js';
import { gatewayTestEnv } from './support.js';

interface Forwarded {
  readonly url: string;
  readonly method: string;
  readonly headers: Headers;
  readonly body: string | undefined;
}

let issuer: TestTokenIssuer;
let t: HttpTestApp | undefined;
let forwarded: Forwarded[];
const logger = createLogger({ service: 'api-gateway', level: 'silent' });

/** Backend stand-in: records forwarded requests and answers with `respond`. */
function backend(respond: (request: Forwarded) => Response | Promise<Response>): HttpFetch {
  return async (input, init = {}) => {
    const request: Forwarded = {
      url: input instanceof Request ? input.url : input.toString(),
      method: init.method ?? 'GET',
      headers: new Headers(init.headers),
      body: typeof init.body === 'string' ? init.body : undefined,
    };
    forwarded.push(request);
    return respond(request);
  };
}

async function start(
  fetchFn: HttpFetch,
  options: {
    env?: Record<string, string>;
    sessionChecker?: IntrospectionSessionChecker | null;
  } = {},
) {
  t = await createHttpTestApp(
    AppModule.register(loadGatewayEnv(gatewayTestEnv(options.env)), {
      fetch: fetchFn,
      verifier: createTokenVerifier({
        issuer: issuer.issuer,
        audience: issuer.audience,
        keys: issuer.getKey,
      }),
      sessionChecker: options.sessionChecker ?? null,
      logger,
    }),
    (app) => {
      configureServiceApp(app, {
        service: 'api-gateway',
        version: '0.0.0-test',
        logger,
        corsAllowedOrigins: [],
        swaggerEnabled: false,
      });
    },
  );
  return t;
}

const ok = () => Response.json({ data: { ok: true } });
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

beforeAll(async () => {
  issuer = await createTestTokenIssuer();
});

afterEach(async () => {
  await t?.close();
  t = undefined;
  forwarded = [];
});

forwarded = [];

describe('gateway authentication', () => {
  it.each([
    ['get', '/api/v1/me'],
    ['get', '/api/v1/me/sessions'],
    ['post', '/api/v1/auth/logout'],
    ['get', '/api/v1/users'],
    ['get', '/api/v1/roles'],
    ['get', '/api/v1/audit-logs'],
  ] as const)(
    '%s %s is rejected without a token and never reaches the backend',
    async (method, path) => {
      const app = await start(backend(ok));
      const res = await app.http[method](path).expect(401);
      expect(res.headers['www-authenticate']).toContain('Bearer');
      expect(forwarded).toEqual([]);
    },
  );

  it('rejects expired and forged tokens', async () => {
    const app = await start(backend(ok));
    const expired = await issuer.sign({ sub: randomUUID() }, { expiresInSeconds: -300 });
    await app.http.get('/api/v1/me').set(bearer(expired)).expect(401);
    const forged = await issuer.sign(
      { sub: randomUUID(), roles: ['super-admin'] },
      { untrustedKey: true },
    );
    await app.http.get('/api/v1/users').set(bearer(forged)).expect(401);
    expect(forwarded).toEqual([]);
  });

  it('forwards authenticated requests with the token, correlation ID and client IP', async () => {
    const app = await start(
      backend(() =>
        Response.json(
          { data: { id: 'x' } },
          { status: 200, headers: { 'cache-control': 'no-store' } },
        ),
      ),
    );
    const token = await issuer.tokenFor(randomUUID(), ['viewer']);
    const res = await app.http
      .patch('/api/v1/me?verbose=1')
      .set(bearer(token))
      .set('x-correlation-id', 'corr-12345678')
      .set('cookie', 'session=should-not-leak')
      .send({ timezone: 'UTC' })
      .expect(200);
    expect(res.body).toEqual({ data: { id: 'x' } });
    expect(res.headers['cache-control']).toBe('no-store');
    expect(forwarded).toHaveLength(1);
    const request = forwarded[0]!;
    expect(request.url).toBe('http://identity-service.internal:4000/api/v1/me?verbose=1');
    expect(request.method).toBe('PATCH');
    expect(request.headers.get('authorization')).toBe(`Bearer ${token}`);
    expect(request.headers.get('x-correlation-id')).toBe('corr-12345678');
    expect(request.headers.get('x-forwarded-for')).toBeTruthy();
    expect(request.headers.get('cookie')).toBeNull();
    expect(JSON.parse(request.body!)).toEqual({ timezone: 'UTC' });
  });

  it('relays backend errors unchanged', async () => {
    const app = await start(
      backend(() =>
        Response.json({ error: { code: 'NOT_FOUND', message: 'User not found' } }, { status: 404 }),
      ),
    );
    const token = await issuer.tokenFor(randomUUID(), ['administrator']);
    const res = await app.http.get(`/api/v1/users/${randomUUID()}`).set(bearer(token)).expect(404);
    expect(res.body).toMatchObject({ error: { code: 'NOT_FOUND' } });
  });
});

describe('gateway authorization', () => {
  it('enforces coarse permissions before forwarding', async () => {
    const app = await start(backend(ok));
    const viewer = await issuer.tokenFor(randomUUID(), ['viewer']);
    const admin = await issuer.tokenFor(randomUUID(), ['administrator']);

    await app.http.get('/api/v1/users').set(bearer(viewer)).expect(403);
    await app.http.get('/api/v1/audit-logs').set(bearer(viewer)).expect(403);
    expect(forwarded).toEqual([]);

    await app.http.get('/api/v1/users').set(bearer(admin)).expect(200);
    await app.http.get('/api/v1/audit-logs?page=2').set(bearer(admin)).expect(200);
    await app.http.get('/api/v1/roles').set(bearer(viewer)).expect(200);
    expect(forwarded.map((request) => new URL(request.url).pathname)).toEqual([
      '/api/v1/users',
      '/api/v1/audit-logs',
      '/api/v1/roles',
    ]);
  });

  it('refuses dot segments and encoded separators that could reach another route', async () => {
    const app = await start(backend(ok));
    const viewer = await issuer.tokenFor(randomUUID(), ['viewer']);
    await app.http.get('/api/v1/me/%2e%2e/users').set(bearer(viewer)).expect(400);
    await app.http.get('/api/v1/me/..%2fusers').set(bearer(viewer)).expect(400);
    expect(forwarded).toEqual([]);
  });

  it('accepts only JSON request bodies', async () => {
    const app = await start(backend(ok));
    const viewer = await issuer.tokenFor(randomUUID(), ['viewer']);
    await app.http
      .patch('/api/v1/me')
      .set(bearer(viewer))
      .set('content-type', 'text/plain')
      .send('timezone=UTC')
      .expect(415);
    expect(forwarded).toEqual([]);
  });
});

describe('backend failures', () => {
  it('answers 502 when the backend is unreachable and 504 on timeout', async () => {
    const viewer = await issuer.tokenFor(randomUUID(), ['viewer']);
    let app = await start(backend(() => Promise.reject(new TypeError('fetch failed'))));
    const res = await app.http.get('/api/v1/me').set(bearer(viewer)).expect(502);
    expect(res.body).toMatchObject({ error: { code: 'BAD_GATEWAY' } });
    await app.close();

    app = await start(
      backend(() => {
        const error = new Error('timed out');
        error.name = 'TimeoutError';
        return Promise.reject(error);
      }),
    );
    await app.http.get('/api/v1/me').set(bearer(viewer)).expect(504);
  });
});

describe('session liveness', () => {
  it('rejects tokens whose Keycloak session ended and stops accepting a session after logout', async () => {
    const userId = randomUUID();
    const sid = randomUUID();
    const token = await issuer.tokenFor(userId, ['viewer'], { sid });
    const introspections: string[] = [];
    let active = true;
    const checker = new IntrospectionSessionChecker({
      introspectionUrl: 'http://keycloak.internal:8180/introspect',
      clientId: 'cve-api',
      clientSecret: 'test-introspection-secret',
      cacheTtlMs: 60_000,
      fetch: (_input, init) => {
        introspections.push(typeof init?.body === 'string' ? init.body : '');
        return Promise.resolve(Response.json({ active, sub: userId }));
      },
    });
    const app = await start(
      backend(() => Response.json({ data: { revokedSessions: 1 } })),
      { sessionChecker: checker },
    );

    await app.http.get('/api/v1/me').set(bearer(token)).expect(200);
    await app.http.get('/api/v1/me').set(bearer(token)).expect(200);
    expect(introspections).toHaveLength(1);

    await app.http.post('/api/v1/auth/logout').set(bearer(token)).expect(200);
    // Cached as active for 60 s, but the gateway saw the logout and invalidated the session.
    const res = await app.http.get('/api/v1/me').set(bearer(token)).expect(401);
    expect(res.headers['www-authenticate']).toContain('invalid_token');

    // Another session revoked elsewhere (e.g. by an administrator) is rejected once Keycloak says so.
    active = false;
    const other = await issuer.tokenFor(userId, ['viewer'], { sid: randomUUID() });
    await app.http.get('/api/v1/me').set(bearer(other)).expect(401);
  });

  it('fails closed when Keycloak cannot confirm the session', async () => {
    const checker = new IntrospectionSessionChecker({
      introspectionUrl: 'http://keycloak.internal:8180/introspect',
      clientId: 'cve-api',
      clientSecret: 'test-introspection-secret',
      fetch: () => Promise.reject(new TypeError('fetch failed')),
    });
    const app = await start(backend(ok), { sessionChecker: checker });
    const token = await issuer.tokenFor(randomUUID(), ['viewer']);
    await app.http.get('/api/v1/me').set(bearer(token)).expect(503);
    expect(forwarded).toEqual([]);
  });
});

describe('rate limiting', () => {
  it('limits each authenticated user separately', async () => {
    const app = await start(backend(ok), { env: { RATE_LIMIT_MAX: '2' } });
    const alice = await issuer.tokenFor(randomUUID(), ['viewer']);
    const bob = await issuer.tokenFor(randomUUID(), ['viewer']);
    await app.http.get('/api/v1/me').set(bearer(alice)).expect(200);
    await app.http.get('/api/v1/me').set(bearer(alice)).expect(200);
    const limited = await app.http.get('/api/v1/me').set(bearer(alice)).expect(429);
    expect(limited.body).toMatchObject({ error: { code: 'TOO_MANY_REQUESTS' } });
    await app.http.get('/api/v1/me').set(bearer(bob)).expect(200);
  });

  it('applies the stricter authentication limit to logout', async () => {
    const app = await start(backend(() => Response.json({ data: { revokedSessions: 0 } })));
    const token = await issuer.tokenFor(randomUUID(), ['viewer']);
    for (let i = 0; i < 20; i += 1) {
      await app.http.post('/api/v1/auth/logout').set(bearer(token)).expect(200);
    }
    await app.http.post('/api/v1/auth/logout').set(bearer(token)).expect(429);
  });
});

describe('Intelligence Service routes', () => {
  it('requires data-source:read to read and data-source:manage to queue runs', async () => {
    const app = await start(backend(ok));
    const viewer = await issuer.tokenFor(randomUUID(), ['viewer']);
    const analyst = await issuer.tokenFor(randomUUID(), ['security-analyst']);
    const admin = await issuer.tokenFor(randomUUID(), ['administrator']);

    await app.http.get('/api/v1/sources').expect(401);
    await app.http.get('/api/v1/sources').set(bearer(viewer)).expect(403);
    await app.http.get('/api/v1/sources/nvd').set(bearer(analyst)).expect(200);
    await app.http.get('/api/v1/sync-runs?source=nvd').set(bearer(analyst)).expect(200);
    await app.http.post('/api/v1/sources/nvd/sync').set(bearer(analyst)).send({}).expect(403);
    await app.http.post('/api/v1/sources/nvd/sync').set(bearer(admin)).send({}).expect(200);
    await app.http.delete('/api/v1/sources/nvd').set(bearer(admin)).expect(404);

    expect(forwarded.map((request) => `${request.method} ${request.url}`)).toEqual([
      'GET http://intelligence-service.internal:4000/api/v1/sources/nvd',
      'GET http://intelligence-service.internal:4000/api/v1/sync-runs?source=nvd',
      'POST http://intelligence-service.internal:4000/api/v1/sources/nvd/sync',
    ]);
  });
});

describe('Asset Service routes', () => {
  it('requires asset:read to read and asset:manage to write', async () => {
    const app = await start(backend(ok));
    const viewer = await issuer.tokenFor(randomUUID(), ['viewer']);
    const researcher = await issuer.tokenFor(randomUUID(), ['vulnerability-researcher']);
    const analyst = await issuer.tokenFor(randomUUID(), ['security-analyst']);
    const id = '00000000-0000-4000-8000-000000000001';

    await app.http.get('/api/v1/vendors').expect(401);
    await app.http.get('/api/v1/vendors?q=acme').set(bearer(viewer)).expect(200);
    await app.http.get(`/api/v1/products/${id}/vulnerabilities`).set(bearer(viewer)).expect(200);
    await app.http
      .get('/api/v1/cve-associations?cveId=CVE-2026-90001')
      .set(bearer(viewer))
      .expect(200);
    await app.http.post('/api/v1/vendors').set(bearer(viewer)).send({}).expect(403);
    await app.http.post('/api/v1/products').set(bearer(researcher)).send({}).expect(403);
    await app.http.patch(`/api/v1/products/${id}`).set(bearer(viewer)).send({}).expect(403);
    await app.http
      .put(`/api/v1/products/${id}/vulnerabilities/CVE-2026-90001`)
      .set(bearer(viewer))
      .send({})
      .expect(403);
    await app.http.delete(`/api/v1/vendors/${id}`).set(bearer(viewer)).expect(403);
    await app.http.post('/api/v1/vendors').set(bearer(analyst)).send({ name: 'x' }).expect(200);
    await app.http.delete(`/api/v1/vendors/${id}`).set(bearer(analyst)).expect(200);

    expect(forwarded.map((request) => `${request.method} ${request.url}`)).toEqual([
      'GET http://asset-service.internal:4000/api/v1/vendors?q=acme',
      `GET http://asset-service.internal:4000/api/v1/products/${id}/vulnerabilities`,
      'GET http://asset-service.internal:4000/api/v1/cve-associations?cveId=CVE-2026-90001',
      'POST http://asset-service.internal:4000/api/v1/vendors',
      `DELETE http://asset-service.internal:4000/api/v1/vendors/${id}`,
    ]);
  });
});

describe('PoC Service routes', () => {
  it('requires poc:read to read and poc:manage to write', async () => {
    const app = await start(backend(ok));
    const viewer = await issuer.tokenFor(randomUUID(), ['viewer']);
    const analyst = await issuer.tokenFor(randomUUID(), ['security-analyst']);
    const researcher = await issuer.tokenFor(randomUUID(), ['vulnerability-researcher']);
    const id = '00000000-0000-4000-8000-000000000001';

    await app.http.get('/api/v1/poc-repositories').expect(401);
    await app.http
      .get('/api/v1/poc-repositories?cveId=CVE-2026-900001')
      .set(bearer(viewer))
      .expect(200);
    await app.http.get(`/api/v1/poc-artifacts/${id}`).set(bearer(analyst)).expect(200);
    await app.http.get('/api/v1/poc-connectors').set(bearer(viewer)).expect(200);
    await app.http.post('/api/v1/poc-associations').set(bearer(viewer)).send({}).expect(403);
    await app.http
      .patch(`/api/v1/poc-associations/${id}`)
      .set(bearer(analyst))
      .send({})
      .expect(403);
    await app.http
      .post(`/api/v1/poc-artifacts/${id}/verification`)
      .set(bearer(viewer))
      .send({})
      .expect(403);
    await app.http.post('/api/v1/poc-discovery-runs').set(bearer(analyst)).send({}).expect(403);
    await app.http
      .post('/api/v1/poc-discovery-runs')
      .set(bearer(researcher))
      .send({ mode: 'recent', connector: 'github' })
      .expect(200);

    expect(forwarded.map((request) => `${request.method} ${request.url}`)).toEqual([
      'GET http://poc-service.internal:4000/api/v1/poc-repositories?cveId=CVE-2026-900001',
      `GET http://poc-service.internal:4000/api/v1/poc-artifacts/${id}`,
      'GET http://poc-service.internal:4000/api/v1/poc-connectors',
      'POST http://poc-service.internal:4000/api/v1/poc-discovery-runs',
    ]);
  });
});

describe('CVE Service routes', () => {
  it('requires cve:read to read and cve:manage to write', async () => {
    const app = await start(backend(ok));
    const viewer = await issuer.tokenFor(randomUUID(), ['viewer']);
    const analyst = await issuer.tokenFor(randomUUID(), ['security-analyst']);
    const admin = await issuer.tokenFor(randomUUID(), ['administrator']);

    await app.http.get('/api/v1/cves').expect(401);
    await app.http.get('/api/v1/cves?severity=critical').set(bearer(viewer)).expect(200);
    await app.http.get('/api/v1/cves/CVE-2026-90001/cvss-history').set(bearer(viewer)).expect(200);
    await app.http.post('/api/v1/cves').set(bearer(viewer)).send({}).expect(403);
    await app.http.put('/api/v1/cves/CVE-2026-90001').set(bearer(analyst)).send({}).expect(403);
    await app.http.patch('/api/v1/cves/CVE-2026-90001').set(bearer(analyst)).send({}).expect(403);
    await app.http.delete('/api/v1/cves/CVE-2026-90001').set(bearer(viewer)).expect(403);
    await app.http
      .post('/api/v1/cves/CVE-2026-90001/epss')
      .set(bearer(viewer))
      .send({})
      .expect(403);
    await app.http.delete('/api/v1/cves/CVE-2026-90001').set(bearer(admin)).expect(200);

    expect(forwarded.map((request) => `${request.method} ${request.url}`)).toEqual([
      'GET http://cve-service.internal:4000/api/v1/cves?severity=critical',
      'GET http://cve-service.internal:4000/api/v1/cves/CVE-2026-90001/cvss-history',
      'DELETE http://cve-service.internal:4000/api/v1/cves/CVE-2026-90001',
    ]);
  });

  it('forwards If-Match and Idempotency-Key and relays ETag', async () => {
    const app = await start(
      backend(() =>
        Response.json(
          { data: { cveId: 'CVE-2026-90001' } },
          { status: 201, headers: { etag: '"1"', 'idempotent-replayed': 'true' } },
        ),
      ),
    );
    const admin = await issuer.tokenFor(randomUUID(), ['administrator']);
    const res = await app.http
      .post('/api/v1/cves')
      .set(bearer(admin))
      .set('idempotency-key', 'synthetic-key-1')
      .set('if-match', '"1"')
      .send({ cveId: 'CVE-2026-90001' })
      .expect(201);
    expect(res.headers['etag']).toBe('"1"');
    expect(res.headers['idempotent-replayed']).toBe('true');
    expect(forwarded[0]?.headers.get('idempotency-key')).toBe('synthetic-key-1');
    expect(forwarded[0]?.headers.get('if-match')).toBe('"1"');
  });
});
