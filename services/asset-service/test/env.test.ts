import { describe, expect, it } from 'vitest';

import { EnvValidationError } from '@cve/config';

import { loadServiceEnv } from '../src/config/env.js';
import { assetTestEnv } from './support.js';

describe('asset-service environment', () => {
  it('uses the registered default port and enables messaging by default', () => {
    const env = loadServiceEnv(
      assetTestEnv({ OUTBOX_RELAY_ENABLED: 'true', EVENT_CONSUMERS_ENABLED: 'true' }),
    );
    expect(env.PORT).toBe(4004);
    expect(env.OUTBOX_RELAY_ENABLED).toBe(true);
    expect(env.EVENT_CONSUMERS_ENABLED).toBe(true);
    expect(env.PROCESSED_EVENT_RETENTION_DAYS).toBe(30);
  });

  it('fails fast when required variables are missing', () => {
    expect(() => loadServiceEnv({})).toThrow(EnvValidationError);
  });

  it('requires the Keycloak URLs', () => {
    const { KEYCLOAK_URL: _omitted, ...rest } = assetTestEnv();
    expect(() => loadServiceEnv(rest)).toThrow(EnvValidationError);
  });

  it("refuses another service's database", () => {
    expect(() =>
      loadServiceEnv(
        assetTestEnv({
          DATABASE_URL: 'postgresql://other_service:pw@127.0.0.1:5432/other_service',
        }),
      ),
    ).toThrow(/must connect to its own database/);
  });
});
