import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  DisallowedUrlError,
  SourceHttpError,
  SourceResponseError,
  SourceTimeoutError,
} from '../src/http/errors.js';
import { SlidingWindowRateLimiter } from '../src/http/rate-limiter.js';
import {
  backoffDelayMs,
  DEFAULT_RETRY_POLICY,
  loggableUrl,
  parseRetryAfter,
  SourceHttpClient,
  type RequestMeter,
} from '../src/http/source-http-client.js';
import { MockSource } from './mock-source.js';
import { silentLogger } from './support.js';

let mock: MockSource;
beforeAll(async () => {
  mock = await new MockSource().start();
});
afterAll(async () => {
  await mock.stop();
});
beforeEach(() => {
  mock.requests.length = 0;
});

function client(overrides: Partial<ConstructorParameters<typeof SourceHttpClient>[0]> = {}) {
  return new SourceHttpClient({
    source: 'nvd',
    allowedOrigins: [mock.origin],
    rateLimiter: new SlidingWindowRateLimiter({ maxRequests: 100, windowMs: 1_000 }),
    timeoutMs: 1_000,
    maxResponseBytes: 1_024,
    userAgent: 'cve-platform-test',
    logger: silentLogger,
    retry: { maxAttempts: 3, baseDelayMs: 5, maxDelayMs: 20, maxRetryAfterMs: 2_000 },
    ...overrides,
  });
}

const okSchema = z.object({ ok: z.boolean() });

describe('SlidingWindowRateLimiter', () => {
  it('allows maxRequests per window and then waits', () => {
    let now = 0;
    const limiter = new SlidingWindowRateLimiter({ maxRequests: 2, windowMs: 1_000 }, () => now);
    return (async () => {
      await limiter.acquire();
      await limiter.acquire();
      expect(limiter.delayMs()).toBe(1_000);
      now = 600;
      expect(limiter.delayMs()).toBe(400);
      now = 1_000;
      expect(limiter.delayMs()).toBe(0);
    })();
  });

  it('spaces requests by minIntervalMs and honours pauses', async () => {
    let now = 0;
    const limiter = new SlidingWindowRateLimiter(
      { maxRequests: 10, windowMs: 1_000, minIntervalMs: 300 },
      () => now,
    );
    await limiter.acquire();
    expect(limiter.delayMs()).toBe(300);
    limiter.pauseUntil(5_000);
    expect(limiter.delayMs()).toBe(5_000);
    now = 5_000;
    expect(limiter.delayMs()).toBe(0);
  });

  it('really throttles callers in order', async () => {
    const limiter = new SlidingWindowRateLimiter({ maxRequests: 2, windowMs: 150 });
    const started = Date.now();
    await Promise.all([limiter.acquire(), limiter.acquire(), limiter.acquire()]);
    expect(Date.now() - started).toBeGreaterThanOrEqual(140);
  });

  it('stops waiting when aborted', async () => {
    const limiter = new SlidingWindowRateLimiter({ maxRequests: 1, windowMs: 60_000 });
    await limiter.acquire();
    const controller = new AbortController();
    const waiting = limiter.acquire(controller.signal);
    controller.abort(new Error('stop'));
    await expect(waiting).rejects.toThrow('stop');
  });
});

describe('retry helpers', () => {
  it('parses Retry-After seconds and dates', () => {
    expect(parseRetryAfter('3', 0)).toBe(3_000);
    expect(parseRetryAfter(new Date(10_000).toUTCString(), 4_000)).toBe(6_000);
    expect(parseRetryAfter('soon', 0)).toBeUndefined();
    expect(parseRetryAfter(null, 0)).toBeUndefined();
  });

  it('backs off exponentially with full jitter and a cap', () => {
    expect(backoffDelayMs(1, DEFAULT_RETRY_POLICY, () => 1)).toBe(1_000);
    expect(backoffDelayMs(3, DEFAULT_RETRY_POLICY, () => 1)).toBe(4_000);
    expect(backoffDelayMs(20, DEFAULT_RETRY_POLICY, () => 1)).toBe(30_000);
    expect(backoffDelayMs(3, DEFAULT_RETRY_POLICY, () => 0.5)).toBe(2_000);
  });

  it('never logs query strings', () => {
    expect(loggableUrl('https://api.example.test/x?apiKey=secret')).toBe(
      'https://api.example.test/x',
    );
  });
});

describe('SourceHttpClient (mocked upstream)', () => {
  it('validates responses against the schema and counts requests', async () => {
    mock.route('/ok', () => ({ body: { ok: true } }));
    const meter: RequestMeter = { requests: 0 };
    const response = await client().getJson(`${mock.origin}/ok`, okSchema, {
      meter,
      headers: { apiKey: 'k' },
    });
    expect(response.body).toEqual({ ok: true });
    expect(meter.requests).toBe(1);
    expect(mock.requests[0]?.headers['user-agent']).toBe('cve-platform-test');
    expect(mock.requests[0]?.headers['apikey']).toBe('k');

    mock.route('/bad', () => ({ body: { ok: 'yes' } }));
    await expect(client().getJson(`${mock.origin}/bad`, okSchema)).rejects.toBeInstanceOf(
      SourceResponseError,
    );
    mock.route('/garbage', () => ({ body: '{not json' }));
    await expect(client().getJson(`${mock.origin}/garbage`, okSchema)).rejects.toThrow(
      /Invalid JSON/,
    );
  });

  it('retries 5xx and honours Retry-After', async () => {
    mock.sequence('/flaky', [
      { status: 503 },
      { status: 429, headers: { 'retry-after': '1' } },
      { body: { ok: true } },
    ]);
    const started = Date.now();
    await expect(client().getJson(`${mock.origin}/flaky`, okSchema)).resolves.toMatchObject({
      body: { ok: true },
    });
    expect(mock.requestsTo('/flaky')).toHaveLength(3);
    expect(Date.now() - started).toBeGreaterThanOrEqual(950);
  });

  it('gives up after maxAttempts and does not retry client errors', async () => {
    mock.route('/down', () => ({ status: 500 }));
    await expect(client().getJson(`${mock.origin}/down`, okSchema)).rejects.toMatchObject({
      status: 500,
      retryable: true,
    });
    expect(mock.requestsTo('/down')).toHaveLength(3);
    mock.route('/missing', () => ({ status: 404 }));
    await expect(client().getJson(`${mock.origin}/missing`, okSchema)).rejects.toBeInstanceOf(
      SourceHttpError,
    );
    expect(mock.requestsTo('/missing')).toHaveLength(1);
  });

  it('fails a Retry-After longer than the allowed wait instead of blocking', async () => {
    mock.route('/later', () => ({ status: 503, headers: { 'retry-after': '3600' } }));
    await expect(client().getJson(`${mock.origin}/later`, okSchema)).rejects.toMatchObject({
      retryAfterMs: 3_600_000,
    });
    expect(mock.requestsTo('/later')).toHaveLength(1);
  });

  it('times out slow responses (and retries them)', async () => {
    mock.route('/slow', () => ({ delayMs: 300, body: { ok: true } }));
    await expect(
      client({ timeoutMs: 100 }).getJson(`${mock.origin}/slow`, okSchema),
    ).rejects.toBeInstanceOf(SourceTimeoutError);
    expect(mock.requestsTo('/slow')).toHaveLength(3);
  });

  it('enforces the response size limit and the content type', async () => {
    mock.route('/big', () => ({ body: { ok: true, padding: 'x'.repeat(5_000) } }));
    await expect(client().getJson(`${mock.origin}/big`, okSchema)).rejects.toThrow(
      /exceeds 1024 bytes/,
    );
    mock.route('/html', () => ({
      headers: { 'content-type': 'text/html' },
      body: '<html></html>',
    }));
    await expect(client().getJson(`${mock.origin}/html`, okSchema)).rejects.toThrow(/content type/);
  });

  it('refuses URLs and redirects outside the allowlist', async () => {
    expect(() => client().assertAllowed('https://evil.example/x')).toThrow(DisallowedUrlError);
    expect(() => client().assertAllowed(`http://user:pw@${mock.origin.slice(7)}/x`)).toThrow(
      /credentials/,
    );
    mock.route('/redirect-out', () => ({
      status: 302,
      headers: { location: 'https://evil.example/' },
    }));
    await expect(client().getJson(`${mock.origin}/redirect-out`, okSchema)).rejects.toBeInstanceOf(
      DisallowedUrlError,
    );
    mock.route('/redirect-in', () => ({ status: 301, headers: { location: '/ok' } }));
    mock.route('/ok', () => ({ body: { ok: true } }));
    await expect(client().getJson(`${mock.origin}/redirect-in`, okSchema)).resolves.toMatchObject({
      url: `${mock.origin}/ok`,
    });
  });

  it('returns not-modified for conditional requests', async () => {
    mock.route('/cond', () => ({ status: 304 }));
    await expect(
      client().getJson(`${mock.origin}/cond`, okSchema, {
        allowNotModified: true,
        headers: { 'if-none-match': '"x"' },
      }),
    ).resolves.toMatchObject({ notModified: true });
  });

  it('stops immediately when the caller aborts', async () => {
    mock.route('/hang', () => ({ delayMs: 500, body: { ok: true } }));
    const controller = new AbortController();
    const pending = client({ timeoutMs: 5_000 }).getJson(`${mock.origin}/hang`, okSchema, {
      signal: controller.signal,
    });
    setTimeout(() => {
      controller.abort(new Error('job cancelled'));
    }, 50);
    await expect(pending).rejects.toThrow('job cancelled');
    expect(mock.requestsTo('/hang')).toHaveLength(1);
  });
});
