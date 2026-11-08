import { describe, expect, it } from 'vitest';

import { parseServerEnv } from './env';

const SECRET = 'x'.repeat(48);

describe('parseServerEnv', () => {
  it('applies defaults', () => {
    const env = parseServerEnv({ WEB_SESSION_SECRET: SECRET });
    expect(env.API_GATEWAY_INTERNAL_URL).toBe('http://localhost:4000');
    expect(env.KEYCLOAK_REALM).toBe('cve-platform');
    expect(env.KEYCLOAK_WEB_CLIENT_ID).toBe('cve-web');
  });

  it('uses the public Keycloak URL for server calls unless an internal one is set', () => {
    expect(
      parseServerEnv({ WEB_SESSION_SECRET: SECRET, KEYCLOAK_PUBLIC_URL: 'http://kc.example/auth/' })
        .KEYCLOAK_URL,
    ).toBe('http://kc.example/auth');
    expect(
      parseServerEnv({
        WEB_SESSION_SECRET: SECRET,
        KEYCLOAK_PUBLIC_URL: 'http://kc.example/auth',
        KEYCLOAK_URL: 'http://keycloak:8180/auth',
      }).KEYCLOAK_URL,
    ).toBe('http://keycloak:8180/auth');
  });

  it('strips trailing slashes', () => {
    expect(
      parseServerEnv({
        WEB_SESSION_SECRET: SECRET,
        API_GATEWAY_INTERNAL_URL: 'http://api-gateway:4000/',
      }).API_GATEWAY_INTERNAL_URL,
    ).toBe('http://api-gateway:4000');
  });

  it('rejects non-http URLs', () => {
    expect(() =>
      parseServerEnv({ WEB_SESSION_SECRET: SECRET, API_GATEWAY_INTERNAL_URL: 'file:///etc/passwd' }),
    ).toThrow(/API_GATEWAY_INTERNAL_URL/);
  });

  it('requires a long session secret and never echoes it', () => {
    expect(() => parseServerEnv({ WEB_SESSION_SECRET: 'short-secret-value' })).toThrow(
      /WEB_SESSION_SECRET must be at least 32 characters/,
    );
    try {
      parseServerEnv({ WEB_SESSION_SECRET: 'short-secret-value' });
    } catch (error) {
      expect(String(error)).not.toContain('short-secret-value');
    }
  });

  it('rejects a public origin with a path', () => {
    expect(() =>
      parseServerEnv({ WEB_SESSION_SECRET: SECRET, PUBLIC_ORIGIN: 'http://localhost:8080/app' }),
    ).toThrow(/PUBLIC_ORIGIN/);
  });
});
