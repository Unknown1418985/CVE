import { describe, expect, it } from 'vitest';

import { EnvValidationError } from '@cve/config';
import { buildServiceTestEnv } from '@cve/testing';

import { loadServiceEnv } from '../src/config/env.js';
import { SERVICE_NAME } from '../src/service.js';
import { pocTestEnv } from './support.js';

const base = {
  KEYCLOAK_URL: 'http://keycloak.test/auth',
  KEYCLOAK_PUBLIC_URL: 'http://keycloak.test/auth',
};

describe('poc-service environment', () => {
  it('uses the registered default port and safe defaults', () => {
    const env = pocTestEnv();
    expect(env.PORT).toBe(4005);
    expect(env.POC_CONNECTORS_ENABLED).toEqual(['github', 'cve-references']);
    expect(env.POC_GITHUB_SEARCH_IN).toEqual(['name', 'description', 'topics', 'readme']);
    expect(env.GITHUB_TOKEN).toBeUndefined();
  });

  it('fails fast when required variables are missing', () => {
    expect(() => loadServiceEnv({})).toThrow(EnvValidationError);
  });

  it("refuses another service's database", () => {
    expect(() =>
      loadServiceEnv(
        buildServiceTestEnv(SERVICE_NAME, {
          ...base,
          DATABASE_URL: 'postgresql://other_service:pw@127.0.0.1:5432/other_service',
        }),
      ),
    ).toThrow(/must connect to its own database/);
  });

  it('accepts only approved connectors', () => {
    expect(pocTestEnv({ POC_CONNECTORS_ENABLED: 'github' }).POC_CONNECTORS_ENABLED).toEqual([
      'github',
    ]);
    expect(pocTestEnv({ POC_CONNECTORS_ENABLED: 'none' }).POC_CONNECTORS_ENABLED).toEqual([]);
    expect(() => pocTestEnv({ POC_CONNECTORS_ENABLED: 'github,pastebin' })).toThrow(
      /not approved connectors: pastebin/,
    );
  });

  it('rejects unknown search fields, short tokens and plain HTTP in production', () => {
    expect(() => pocTestEnv({ POC_GITHUB_SEARCH_IN: 'name,code' })).toThrow(EnvValidationError);
    expect(() => pocTestEnv({ GITHUB_TOKEN: 'short' })).toThrow(EnvValidationError);
    expect(() =>
      pocTestEnv({ NODE_ENV: 'production', GITHUB_API_URL: 'http://api.github.com' }),
    ).toThrow(/must use https in production/);
  });
});
