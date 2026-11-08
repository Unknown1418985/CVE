import type { HealthIndicator } from '@cve/shared';

import type { HttpFetch } from '../services-health/services-health.constants.js';

/**
 * Readiness check for the identity provider: the gateway cannot authenticate anyone without the
 * realm's signing keys, so an unreachable or invalid JWKS endpoint makes it not ready.
 */
export function createKeycloakHealthIndicator(
  jwksUrl: string,
  fetchFn: HttpFetch,
): HealthIndicator {
  return {
    name: 'keycloak',
    critical: true,
    async check(timeoutMs) {
      const started = performance.now();
      const latency = () => Math.round(performance.now() - started);
      try {
        const response = await fetchFn(jwksUrl, {
          method: 'GET',
          headers: { accept: 'application/json' },
          redirect: 'manual',
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok) {
          await response.body?.cancel();
          return {
            name: 'keycloak',
            status: 'down',
            latencyMs: latency(),
            message: `JWKS returned HTTP ${String(response.status)}`,
          };
        }
        const body = (await response.json()) as { keys?: unknown };
        const usable = Array.isArray(body.keys) && body.keys.length > 0;
        return {
          name: 'keycloak',
          status: usable ? 'ok' : 'down',
          latencyMs: latency(),
          message: usable ? 'signing keys available' : 'JWKS contains no keys',
        };
      } catch (error) {
        return {
          name: 'keycloak',
          status: 'down',
          latencyMs: latency(),
          message: error instanceof Error ? error.message : String(error),
        };
      }
    },
  };
}
