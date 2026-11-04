import { describe, expect, it } from 'vitest';

import {
  buildCorsOptions,
  generateCorrelationId,
  isValidCorrelationId,
  resolveCorrelationId,
} from './index.js';

function checkOrigin(allowed: string[], origin: string | undefined): boolean | undefined {
  let result: boolean | undefined;
  buildCorsOptions(allowed).origin(origin, (_error, allow) => {
    result = allow;
  });
  return result;
}

describe('buildCorsOptions', () => {
  it('allows only configured origins', () => {
    expect(checkOrigin(['https://cve.example.com'], 'https://cve.example.com')).toBe(true);
    expect(checkOrigin(['https://cve.example.com'], 'https://evil.example.com')).toBe(false);
    expect(checkOrigin([], 'https://cve.example.com')).toBe(false);
  });

  it('allows requests without an Origin header', () => {
    expect(checkOrigin([], undefined)).toBe(true);
  });

  it('rejects wildcards and origins with paths', () => {
    expect(() => buildCorsOptions(['*'])).toThrow(/Wildcard/);
    expect(() => buildCorsOptions(['https://*.example.com'])).toThrow(/Wildcard/);
    expect(() => buildCorsOptions(['https://cve.example.com/app'])).toThrow(/bare origin/);
  });
});

describe('correlation IDs', () => {
  it('accepts safe identifiers and generates UUIDs', () => {
    expect(isValidCorrelationId(generateCorrelationId())).toBe(true);
    expect(isValidCorrelationId('req-12345678')).toBe(true);
  });

  it('replaces unsafe or missing identifiers', () => {
    const injected = 'abc\n{"level":"fatal"}';
    expect(resolveCorrelationId(injected)).not.toBe(injected);
    expect(resolveCorrelationId(undefined)).toMatch(/^[0-9a-f-]{36}$/);
    expect(resolveCorrelationId('short')).not.toBe('short');
    expect(resolveCorrelationId(['req-12345678', 'other'])).toBe('req-12345678');
  });
});

describe('header constants', () => {
  it('stay aligned with @cve/contracts', async () => {
    const contracts = await import('@cve/contracts');
    const local = await import('./constants.js');
    expect(local.CORRELATION_ID_HEADER_NAME).toBe(contracts.CORRELATION_ID_HEADER);
    expect(local.IDEMPOTENCY_KEY_HEADER_NAME).toBe(contracts.IDEMPOTENCY_KEY_HEADER);
  });
});
