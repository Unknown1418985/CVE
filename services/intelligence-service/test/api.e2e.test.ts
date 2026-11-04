import 'reflect-metadata';

import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  apiErrorResponseSchema,
  apiPaginatedResponseSchema,
  sourceStatusSchema,
  syncRunDetailSchema,
  syncRunSchema,
  triggerSyncResponseSchema,
  type Role,
} from '@cve/contracts';
import { createTestTokenIssuer, type TestTokenIssuer } from '@cve/testing/auth';

import { startApp, type AppContext } from './app-support.js';

let issuer: TestTokenIssuer;
let ctx: AppContext;
let admin: Record<string, string>;
let analyst: Record<string, string>;
let viewer: Record<string, string>;

async function headersFor(roles: Role[]) {
  return {
    authorization: `Bearer ${await issuer.tokenFor(randomUUID(), roles, { preferred_username: roles[0] ?? 'user' })}`,
  };
}

const data = (body: unknown) => (body as { data: unknown }).data;
const errorOf = (body: unknown) => apiErrorResponseSchema.parse(body).error;

async function seedRun(
  status: 'failed' | 'succeeded',
  source: 'nvd' | 'cisa-kev' = 'nvd',
  startedAt = new Date(),
) {
  const run = await ctx.repository.createRun({
    source,
    trigger: 'scheduled',
    jobId: `scheduled.${source}.${randomUUID()}`,
    attempt: 1,
    requestedBy: null,
    resumedFromRunId: null,
    startedAt,
    cursorBefore: null,
    checkpoint: { windowStart: null, runEnd: startedAt.toISOString(), startIndex: 2 },
  });
  await ctx.repository.saveProgress(run.id, {
    checkpoint: { windowStart: null, runEnd: startedAt.toISOString(), startIndex: 2 },
    stats: {
      requests: 1,
      fetched: 2,
      created: 2,
      updated: 0,
      unchanged: 0,
      removed: 0,
      invalid: 1,
      events: 2,
    },
    issues: [
      { sourceRecordId: 'CVE-2026-90001', message: 'cvssMetrics[0] dropped: invalid vector' },
    ],
    now: startedAt,
  });
  if (status === 'failed') {
    await ctx.repository.failRun(run.id, {
      status: 'failed',
      finishedAt: new Date(startedAt.getTime() + 1_000),
      stats: null,
      error: 'HTTP 503 from https://source',
      events: [],
    });
  } else {
    await ctx.repository.completeRun(run.id, {
      finishedAt: new Date(startedAt.getTime() + 1_000),
      stats: run.stats,
      cursorAfter: { lastModifiedThrough: startedAt.toISOString() },
      issues: [],
      events: [],
    });
  }
  return run;
}

beforeAll(async () => {
  issuer = await createTestTokenIssuer();
  ctx = await startApp(issuer);
  admin = await headersFor(['administrator']);
  analyst = await headersFor(['security-analyst']);
  viewer = await headersFor(['viewer']);
});
afterAll(async () => {
  await ctx.t.close();
});
beforeEach(() => {
  ctx.repository.runs.clear();
  ctx.repository.states.clear();
  ctx.jobs.jobs.clear();
});

describe('authentication and authorisation', () => {
  it('requires a token and data-source permissions', async () => {
    await ctx.t.http.get('/api/v1/sources').expect(401);
    await ctx.t.http.get('/api/v1/sources').set(viewer).expect(403);
    await ctx.t.http.get('/api/v1/sources').set(analyst).expect(200);
    await ctx.t.http.post('/api/v1/sources/nvd/sync').set(analyst).send({}).expect(403);
  });
});

describe('GET /api/v1/sources', () => {
  it('lists every source with terms, quotas and state, without secrets', async () => {
    await seedRun('succeeded', 'nvd');
    const res = await ctx.t.http.get('/api/v1/sources').set(analyst).expect(200);
    const sources = sourceStatusSchema.array().parse(data(res.body));
    expect(sources.map((s) => s.source)).toEqual([
      'nvd',
      'mitre-cve',
      'cisa-kev',
      'first-epss',
      'github-advisory',
    ]);
    const nvd = sources[0];
    expect(nvd).toMatchObject({
      enabled: true,
      schedule: '15 */2 * * *',
      authentication: { mode: 'optional', configured: false },
      rateLimit: { maxRequests: 1_000 },
      storesRawPayloads: true,
      state: { running: false, lastRunStatus: 'succeeded' },
    });
    expect(nvd?.attribution).toMatch(/NVD/);
    expect(JSON.stringify(res.body)).not.toMatch(/apiKey|token/i);
  });

  it('returns one source and refuses unknown ones', async () => {
    const res = await ctx.t.http.get('/api/v1/sources/cisa-kev').set(analyst).expect(200);
    expect(sourceStatusSchema.parse(data(res.body)).license).toBe('CC0 1.0 Universal');
    expect(
      errorOf((await ctx.t.http.get('/api/v1/sources/exploit-db').set(analyst).expect(400)).body)
        .code,
    ).toBe('BAD_REQUEST');
  });
});

describe('POST /api/v1/sources/:source/sync', () => {
  it('queues a manual run with the requesting user and honours Idempotency-Key', async () => {
    const first = await ctx.t.http
      .post('/api/v1/sources/nvd/sync')
      .set(admin)
      .set('Idempotency-Key', 'run-1')
      .send({ fresh: true })
      .expect(202);
    expect(triggerSyncResponseSchema.parse(data(first.body))).toEqual({
      source: 'nvd',
      jobId: 'manual.nvd.run-1',
      queued: true,
    });
    expect(ctx.jobs.jobs.get('manual.nvd.run-1')).toMatchObject({
      source: 'nvd',
      trigger: 'manual',
      fresh: true,
      requestedBy: expect.stringMatching(/^administrator/) as unknown,
    });
    const again = await ctx.t.http
      .post('/api/v1/sources/nvd/sync')
      .set(admin)
      .set('Idempotency-Key', 'run-1')
      .send({})
      .expect(202);
    expect(triggerSyncResponseSchema.parse(data(again.body)).queued).toBe(false);
    // Without a body the defaults apply.
    await ctx.t.http.post('/api/v1/sources/cisa-kev/sync').set(admin).expect(202);
  });

  it('validates the body and the key', async () => {
    await ctx.t.http.post('/api/v1/sources/nvd/sync').set(admin).send({ fresh: 'yes' }).expect(400);
    await ctx.t.http
      .post('/api/v1/sources/nvd/sync')
      .set(admin)
      .send({ unexpected: 1 })
      .expect(400);
    await ctx.t.http
      .post('/api/v1/sources/nvd/sync')
      .set(admin)
      .set('Idempotency-Key', 'a:b')
      .send({})
      .expect(400);
  });
});

describe('synchronisation history', () => {
  it('lists runs newest first with filters and pagination', async () => {
    await seedRun('succeeded', 'nvd', new Date('2026-11-04T08:00:00Z'));
    await seedRun('failed', 'nvd', new Date('2026-11-04T09:00:00Z'));
    await seedRun('succeeded', 'cisa-kev', new Date('2026-11-04T10:00:00Z'));
    const res = await ctx.t.http.get('/api/v1/sync-runs?pageSize=2').set(analyst).expect(200);
    const page = apiPaginatedResponseSchema(syncRunSchema).parse(res.body);
    expect(page.meta).toEqual({ page: 1, pageSize: 2, totalItems: 3, totalPages: 2 });
    expect(page.data.map((r) => r.source)).toEqual(['cisa-kev', 'nvd']);
    const failed = apiPaginatedResponseSchema(syncRunSchema).parse(
      (await ctx.t.http.get('/api/v1/sync-runs?source=nvd&status=failed').set(analyst).expect(200))
        .body,
    );
    expect(failed.data).toHaveLength(1);
    expect(failed.data[0]).toMatchObject({
      status: 'failed',
      error: 'HTTP 503 from https://source',
      issueCount: 1,
    });
    await ctx.t.http.get('/api/v1/sync-runs?status=broken').set(analyst).expect(400);
  });

  it('returns a run with its issues', async () => {
    const run = await seedRun('failed');
    const res = await ctx.t.http.get(`/api/v1/sync-runs/${run.id}`).set(analyst).expect(200);
    expect(syncRunDetailSchema.parse(data(res.body)).issues).toEqual([
      expect.objectContaining({
        sourceRecordId: 'CVE-2026-90001',
        message: 'cvssMetrics[0] dropped: invalid vector',
      }),
    ]);
    await ctx.t.http.get(`/api/v1/sync-runs/${randomUUID()}`).set(analyst).expect(404);
    await ctx.t.http.get('/api/v1/sync-runs/not-a-uuid').set(analyst).expect(400);
  });

  it('retries only the latest failed run of a source', async () => {
    const older = await seedRun('failed', 'nvd', new Date('2026-11-04T08:00:00Z'));
    const latest = await seedRun('failed', 'nvd', new Date('2026-11-04T09:00:00Z'));
    const ok = await seedRun('succeeded', 'cisa-kev');
    await ctx.t.http.post(`/api/v1/sync-runs/${latest.id}/retry`).set(analyst).expect(403);
    const res = await ctx.t.http
      .post(`/api/v1/sync-runs/${latest.id}/retry`)
      .set(admin)
      .expect(202);
    expect(triggerSyncResponseSchema.parse(data(res.body))).toEqual({
      source: 'nvd',
      jobId: `retry.${latest.id}`,
      queued: true,
    });
    expect(ctx.jobs.jobs.get(`retry.${latest.id}`)).toMatchObject({
      fresh: false,
      trigger: 'manual',
    });
    await ctx.t.http.post(`/api/v1/sync-runs/${older.id}/retry`).set(admin).expect(409);
    await ctx.t.http.post(`/api/v1/sync-runs/${ok.id}/retry`).set(admin).expect(409);
  });
});

describe('disabled sources', () => {
  it('cannot be triggered', async () => {
    const { intelligenceTestEnv } = await import('./support.js');
    const disabled = await startApp(issuer, {
      env: intelligenceTestEnv(null, { GITHUB_ADVISORY_ENABLED: 'false' }),
    });
    try {
      const source = sourceStatusSchema.parse(
        data(
          (await disabled.t.http.get('/api/v1/sources/github-advisory').set(analyst).expect(200))
            .body,
        ),
      );
      expect(source).toMatchObject({ enabled: false, schedule: null });
      await disabled.t.http
        .post('/api/v1/sources/github-advisory/sync')
        .set(admin)
        .send({})
        .expect(409);
    } finally {
      await disabled.t.close();
    }
  });
});
