import { describe, expect, it } from 'vitest';

import { EnvValidationError } from '@cve/config';

import { loadServiceEnv } from '../src/config/env.js';
import { identityTestEnv } from './support.js';

describe('identity-service environment', () => {
  it('uses the registered default port and Keycloak defaults', () => {
    const env = loadServiceEnv(identityTestEnv());
    expect(env.PORT).toBe(4001);
    expect(env.KEYCLOAK_REALM).toBe('cve-platform');
    expect(env.KEYCLOAK_AUDIENCE).toBe('cve-api');
    expect(env.KEYCLOAK_ADMIN_CLIENT_ID).toBe('cve-identity-service');
  });

  it('fails fast when required variables are missing', () => {
    expect(() => loadServiceEnv({})).toThrow(EnvValidationError);
    const env = identityTestEnv();
    delete env['KEYCLOAK_ADMIN_CLIENT_SECRET'];
    expect(() => loadServiceEnv(env)).toThrow(/KEYCLOAK_ADMIN_CLIENT_SECRET/);
  });

  it('rejects short secrets and unsafe realm names', () => {
    expect(() =>
      loadServiceEnv(identityTestEnv({ KEYCLOAK_ADMIN_CLIENT_SECRET: 'short' })),
    ).toThrow(EnvValidationError);
    expect(() => loadServiceEnv(identityTestEnv({ KEYCLOAK_REALM: '../master' }))).toThrow(
      EnvValidationError,
    );
  });

  it("refuses another service's database", () => {
    expect(() =>
      loadServiceEnv(
        identityTestEnv({
          DATABASE_URL: 'postgresql://other_service:pw@127.0.0.1:5432/other_service',
        }),
      ),
    ).toThrow(/must connect to its own database/);
  });
});
