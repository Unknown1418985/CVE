import { describe, expect, it } from 'vitest';

import { buildServiceTestEnv } from './env.js';

describe('buildServiceTestEnv', () => {
  it('derives the per-service database and applies overrides', () => {
    const env = buildServiceTestEnv('cve-service', { LOG_LEVEL: 'debug' });
    expect(env['DATABASE_URL']).toContain('/cve_service');
    expect(env['LOG_LEVEL']).toBe('debug');
    expect(env['NODE_ENV']).toBe('test');
  });
});
