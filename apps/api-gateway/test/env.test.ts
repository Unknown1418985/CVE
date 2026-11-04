import { describe, expect, it } from 'vitest';

import { EnvValidationError } from '@cve/config';

import { loadGatewayEnv, serviceRegistryFromEnv, serviceUrlVariable } from '../src/config/env.js';
import { gatewayTestEnv } from './support.js';

describe('api-gateway environment', () => {
  it('derives service URL variable names', () => {
    expect(serviceUrlVariable('cve-service')).toBe('CVE_SERVICE_URL');
  });

  it('builds the service registry without trailing slashes', () => {
    const env = loadGatewayEnv(gatewayTestEnv());
    expect(env.PORT).toBe(4000);
    expect(serviceRegistryFromEnv(env)['cve-service']).toBe('http://cve-service.internal:4000');
  });

  it('requires every backend service URL', () => {
    const env = gatewayTestEnv();
    delete env['POC_SERVICE_URL'];
    expect(() => loadGatewayEnv(env)).toThrow(EnvValidationError);
  });

  it('rejects non-HTTP service URLs', () => {
    expect(() => loadGatewayEnv(gatewayTestEnv({ CVE_SERVICE_URL: 'file:///etc/passwd' }))).toThrow(
      EnvValidationError,
    );
  });
});

describe('api-gateway authentication settings', () => {
  it('requires the introspection secret while session checks are enabled', () => {
    const env = gatewayTestEnv();
    delete env['KEYCLOAK_INTROSPECTION_CLIENT_SECRET'];
    expect(() => loadGatewayEnv(env)).toThrow(/KEYCLOAK_INTROSPECTION_CLIENT_SECRET/);
    expect(() => loadGatewayEnv({ ...env, AUTH_SESSION_CHECK_ENABLED: 'false' })).not.toThrow();
  });

  it('requires the Keycloak URLs', () => {
    const env = gatewayTestEnv();
    delete env['KEYCLOAK_PUBLIC_URL'];
    expect(() => loadGatewayEnv(env)).toThrow(EnvValidationError);
  });
});
