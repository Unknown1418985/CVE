import 'server-only';

/** Header the web client sends on every BFF call; a cross-site form or image cannot set it. */
export const CLIENT_HEADER = 'x-cve-client';
export const CLIENT_HEADER_VALUE = 'web';

interface HeaderSource {
  get(name: string): string | null;
}

/**
 * CSRF defence for state-changing requests: the Origin must be the platform's public origin
 * (or, when a browser omits Origin, Fetch Metadata must report a same-origin request).
 */
export function isSameOriginRequest(headers: HeaderSource, publicOrigin: string): boolean {
  const origin = headers.get('origin');
  if (origin !== null) return origin === publicOrigin;
  return headers.get('sec-fetch-site') === 'same-origin';
}
