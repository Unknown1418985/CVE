import { describe, expect, it } from 'vitest';

import { fetchPlatformHealth } from './platform-health';

const health = {
  status: 'ok',
  timestamp: new Date().toISOString(),
  services: [{ service: 'cve-service', status: 'ok' }],
};

describe('fetchPlatformHealth', () => {
  it('returns validated health data', async () => {
    const result = await fetchPlatformHealth('http://gw', () =>
      Promise.resolve(Response.json({ data: health })),
    );
    expect(result).toEqual({ ok: true, health });
  });

  it('reports HTTP errors instead of fabricating a status', async () => {
    const result = await fetchPlatformHealth('http://gw', () =>
      Promise.resolve(new Response('nope', { status: 502 })),
    );
    expect(result).toEqual({ ok: false, error: 'API Gateway responded with HTTP 502' });
  });

  it('reports malformed payloads', async () => {
    const result = await fetchPlatformHealth('http://gw', () =>
      Promise.resolve(Response.json({ data: { status: 'great' } })),
    );
    expect(result.ok).toBe(false);
  });

  it('reports network failures', async () => {
    const result = await fetchPlatformHealth('http://gw', () =>
      Promise.reject(new TypeError('fetch failed')),
    );
    expect(result).toEqual({ ok: false, error: 'API Gateway is unreachable' });
  });
});
