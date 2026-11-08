import { describe, expect, it } from 'vitest';

import { apiPath, buildQueryString, newIdempotencyKey } from './client';

describe('buildQueryString', () => {
  it('drops empty values and joins lists', () => {
    expect(
      buildQueryString({
        q: '',
        severity: ['critical', 'high'],
        kev: true,
        page: 2,
        empty: [],
        none: undefined,
        nil: null,
      }),
    ).toBe('?severity=critical%2Chigh&kev=true&page=2');
    expect(buildQueryString(undefined)).toBe('');
    expect(buildQueryString({ q: '' })).toBe('');
  });
});

describe('apiPath', () => {
  it('encodes each segment so values cannot add path segments', () => {
    expect(apiPath('users', '../admin', 'sessions')).toBe('users/..%2Fadmin/sessions');
    expect(apiPath('cves', 'CVE-2026-0001')).toBe('cves/CVE-2026-0001');
  });
});

describe('newIdempotencyKey', () => {
  it('matches the API key grammar', () => {
    expect(newIdempotencyKey()).toMatch(/^[A-Za-z0-9._-]{1,64}$/);
  });
});
