import { describe, expect, it } from 'vitest';

import { EnvValidationError } from '@cve/config';
import { buildServiceTestEnv } from '@cve/testing';

import { loadServiceEnv } from '../src/config/env.js';
import { SERVICE_NAME } from '../src/service.js';

const base = (overrides: Record<string, string> = {}) =>
  buildServiceTestEnv(SERVICE_NAME, {
    KEYCLOAK_URL: 'http://keycloak:8180/auth',
    KEYCLOAK_PUBLIC_URL: 'http://localhost:8080/auth',
    ...overrides,
  });

describe('intelligence-service environment', () => {
  it('uses the registered default port and documented source endpoints', () => {
    const env = loadServiceEnv(base());
    expect(env.PORT).toBe(4003);
    expect(env.NVD_API_URL).toBe('https://services.nvd.nist.gov/rest/json/cves/2.0');
    expect(env.CISA_KEV_FEED_URL).toMatch(/^https:\/\/www\.cisa\.gov\//);
    expect(env.NVD_API_KEY).toBeUndefined();
    expect(env.GITHUB_TOKEN).toBeUndefined();
  });

  it('fails fast when required variables are missing', () => {
    expect(() => loadServiceEnv({})).toThrow(EnvValidationError);
  });

  it("refuses another service's database", () => {
    expect(() =>
      loadServiceEnv(
        base({ DATABASE_URL: 'postgresql://other_service:pw@127.0.0.1:5432/other_service' }),
      ),
    ).toThrow(/must connect to its own database/);
  });

  it('treats empty credentials as not configured and rejects short ones', () => {
    expect(loadServiceEnv(base({ NVD_API_KEY: '', GITHUB_TOKEN: '' })).NVD_API_KEY).toBeUndefined();
    expect(() => loadServiceEnv(base({ NVD_API_KEY: 'short' }))).toThrow(EnvValidationError);
  });

  it('requires https source URLs in production', () => {
    expect(() =>
      loadServiceEnv(
        base({ NODE_ENV: 'production', NVD_API_URL: 'http://nvd.example.test/rest/json/cves/2.0' }),
      ),
    ).toThrow(/https/);
    expect(loadServiceEnv(base({ NODE_ENV: 'production' })).NODE_ENV).toBe('production');
  });

  it('validates schedules', () => {
    expect(() => loadServiceEnv(base({ NVD_SYNC_CRON: 'hourly' }))).toThrow(EnvValidationError);
  });
});
