import { z } from 'zod';

import { AuthenticationError, IdentityProviderUnavailableError } from './errors.js';
import type { AuthenticatedPrincipal } from './principal.js';

/**
 * Confirms that the Keycloak session behind a token is still active, so that logout and session
 * revocation take effect before the (short-lived) access token expires.
 */
export interface SessionChecker {
  assertActive(token: string, principal: AuthenticatedPrincipal): Promise<void>;
}

export interface IntrospectionSessionCheckerOptions {
  /** `<keycloak>/realms/<realm>/protocol/openid-connect/token/introspect` (internal address). */
  readonly introspectionUrl: string;
  /** Confidential client allowed to introspect (the `cve-api` resource server). */
  readonly clientId: string;
  readonly clientSecret: string;
  /** How long an "active" answer is reused for the same session. Default 15 s. */
  readonly cacheTtlMs?: number;
  readonly maxCacheEntries?: number;
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
}

const introspectionResponseSchema = z.object({
  active: z.boolean(),
  sub: z.string().optional(),
});

interface CacheEntry {
  readonly active: boolean;
  readonly expiresAt: number;
}

/**
 * RFC 7662 token introspection against Keycloak with a small in-memory cache keyed by session
 * (falling back to token ID). Inactive results are cached until the token itself expires.
 * Fails closed: if Keycloak cannot answer, the request is rejected with 503 upstream.
 */
export class IntrospectionSessionChecker implements SessionChecker {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly fetchFn: typeof fetch;
  private readonly now: () => number;

  constructor(private readonly options: IntrospectionSessionCheckerOptions) {
    this.fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.now = options.now ?? Date.now;
  }

  /** Forgets cached answers for a session, e.g. right after this process revoked it. */
  invalidate(sessionId: string): void {
    this.cache.set(`sid:${sessionId}`, { active: false, expiresAt: this.now() + 15 * 60_000 });
  }

  async assertActive(token: string, principal: AuthenticatedPrincipal): Promise<void> {
    const key =
      principal.sessionId !== undefined
        ? `sid:${principal.sessionId}`
        : principal.tokenId !== undefined
          ? `jti:${principal.tokenId}`
          : undefined;
    const now = this.now();
    const cached = key === undefined ? undefined : this.cache.get(key);
    if (cached && cached.expiresAt > now) {
      if (!cached.active) throw inactive();
      return;
    }

    const active = await this.introspect(token, principal);
    if (key !== undefined) {
      const ttl = active
        ? (this.options.cacheTtlMs ?? 15_000)
        : principal.expiresAt.getTime() - now;
      this.remember(key, { active, expiresAt: now + Math.max(ttl, 1_000) });
    }
    if (!active) throw inactive();
  }

  private remember(key: string, entry: CacheEntry): void {
    const max = this.options.maxCacheEntries ?? 50_000;
    if (this.cache.size >= max) {
      const now = this.now();
      for (const [cachedKey, value] of this.cache) {
        if (value.expiresAt <= now) this.cache.delete(cachedKey);
      }
      // Still full: drop the oldest insertion (Map preserves insertion order).
      while (this.cache.size >= max) {
        const oldest = this.cache.keys().next();
        if (oldest.done === true) break;
        this.cache.delete(oldest.value);
      }
    }
    this.cache.delete(key);
    this.cache.set(key, entry);
  }

  private async introspect(token: string, principal: AuthenticatedPrincipal): Promise<boolean> {
    const credentials = Buffer.from(
      `${encodeURIComponent(this.options.clientId)}:${encodeURIComponent(this.options.clientSecret)}`,
    ).toString('base64');
    let response: Response;
    try {
      response = await this.fetchFn(this.options.introspectionUrl, {
        method: 'POST',
        headers: {
          authorization: `Basic ${credentials}`,
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: new URLSearchParams({ token, token_type_hint: 'access_token' }).toString(),
        redirect: 'error',
        signal: AbortSignal.timeout(this.options.timeoutMs ?? 3_000),
      });
    } catch (error) {
      throw new IdentityProviderUnavailableError('Token introspection failed', { cause: error });
    }
    if (!response.ok) {
      throw new IdentityProviderUnavailableError(
        `Token introspection answered HTTP ${response.status}`,
      );
    }
    const parsed = introspectionResponseSchema.safeParse(await response.json().catch(() => null));
    if (!parsed.success) {
      throw new IdentityProviderUnavailableError('Token introspection returned an invalid body');
    }
    return (
      parsed.data.active && (parsed.data.sub === undefined || parsed.data.sub === principal.subject)
    );
  }
}

function inactive(): AuthenticationError {
  return new AuthenticationError('session-inactive', 'Session is no longer active');
}
