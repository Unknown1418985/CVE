/** Helpers shared by every GitHub REST API client (advisories, repository search, …). */

/** API version pinned for every request (`X-GitHub-Api-Version`). */
export const GITHUB_API_VERSION = '2022-11-28';

/** `x-ratelimit-remaining: 0` → pause until `x-ratelimit-reset` (epoch seconds). */
export function githubQuotaReset(headers: Headers): number | undefined {
  if (headers.get('x-ratelimit-remaining') !== '0') return undefined;
  const reset = Number(headers.get('x-ratelimit-reset'));
  return Number.isFinite(reset) && reset > 0 ? reset * 1_000 : undefined;
}

/** Extracts the `rel="next"` target from a `Link` header. */
export function nextLink(header: string | null): string | null {
  if (header === null) return null;
  for (const part of header.split(',')) {
    const match = /<([^>]+)>\s*;\s*rel="?next"?/.exec(part.trim());
    if (match?.[1] !== undefined) return match[1];
  }
  return null;
}

/** Request headers for the GitHub REST API; the token is optional (public data). */
export function githubHeaders(token: string | undefined): Record<string, string> {
  return {
    accept: 'application/vnd.github+json',
    'x-github-api-version': GITHUB_API_VERSION,
    ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
  };
}
