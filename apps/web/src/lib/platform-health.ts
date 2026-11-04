import 'server-only';

import { API_PREFIX, platformHealthSchema, type PlatformHealth } from '@cve/contracts';

export type PlatformHealthResult =
  | { readonly ok: true; readonly health: PlatformHealth }
  | { readonly ok: false; readonly error: string };

/**
 * Fetches live platform health from the API Gateway. Returns an explicit error result
 * instead of fabricating a status when the gateway is unreachable or answers unexpectedly.
 */
export async function fetchPlatformHealth(
  gatewayUrl: string,
  fetchFn: typeof fetch = fetch,
  timeoutMs = 3_000,
): Promise<PlatformHealthResult> {
  try {
    const response = await fetchFn(`${gatewayUrl}/${API_PREFIX}/health/services`, {
      cache: 'no-store',
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) {
      return { ok: false, error: `API Gateway responded with HTTP ${response.status}` };
    }
    const body: unknown = await response.json();
    const data =
      typeof body === 'object' && body !== null ? (body as { data?: unknown }).data : undefined;
    const parsed = platformHealthSchema.safeParse(data);
    if (!parsed.success) {
      return { ok: false, error: 'API Gateway returned an unexpected health payload' };
    }
    return { ok: true, health: parsed.data };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error && error.name === 'TimeoutError'
          ? 'API Gateway did not respond in time'
          : 'API Gateway is unreachable',
    };
  }
}
