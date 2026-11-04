import { describe, expect, it } from 'vitest';

import { EnvValidationError } from '@cve/config';
import { buildServiceTestEnv } from '@cve/testing';

import { loadServiceEnv } from '../src/config/env.js';
import { SERVICE_NAME } from '../src/service.js';

describe('reporting-service environment', () => {
  it('uses the registered default port', () => {
    expect(loadServiceEnv(buildServiceTestEnv(SERVICE_NAME)).PORT).toBe(4008);
  });

  it('fails fast when required variables are missing', () => {
    expect(() => loadServiceEnv({})).toThrow(EnvValidationError);
  });

  it("refuses another service's database", () => {
    expect(() =>
      loadServiceEnv(
        buildServiceTestEnv(SERVICE_NAME, {
          DATABASE_URL: 'postgresql://other_service:pw@127.0.0.1:5432/other_service',
        }),
      ),
    ).toThrow(/must connect to its own database/);
  });
});
