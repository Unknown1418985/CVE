import { describe, expect, it } from 'vitest';

import { githubHeaders, githubQuotaReset, nextLink } from './github.js';

describe('GitHub helpers', () => {
  it('reads the next page from a Link header', () => {
    expect(
      nextLink(
        '<https://api.github.com/x?page=1>; rel="prev", <https://api.github.com/x?page=3>; rel="next"',
      ),
    ).toBe('https://api.github.com/x?page=3');
    expect(nextLink('<https://api.github.com/x?page=1>; rel="prev"')).toBeNull();
    expect(nextLink(null)).toBeNull();
  });

  it('pauses only when the quota is exhausted', () => {
    expect(
      githubQuotaReset(
        new Headers({ 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1700000000' }),
      ),
    ).toBe(1_700_000_000_000);
    expect(
      githubQuotaReset(
        new Headers({ 'x-ratelimit-remaining': '3', 'x-ratelimit-reset': '1700000000' }),
      ),
    ).toBeUndefined();
    expect(githubQuotaReset(new Headers({ 'x-ratelimit-remaining': '0' }))).toBeUndefined();
  });

  it('sends the token only when configured', () => {
    expect(githubHeaders(undefined)).not.toHaveProperty('authorization');
    expect(githubHeaders('t'.repeat(20))['authorization']).toBe(`Bearer ${'t'.repeat(20)}`);
  });
});
