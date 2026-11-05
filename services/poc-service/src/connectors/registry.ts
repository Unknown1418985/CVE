import type { Logger } from '@cve/logger';
import {
  DEFAULT_RETRY_POLICY,
  githubQuotaReset,
  SlidingWindowRateLimiter,
  SourceHttpClient,
  type RateLimit,
} from '@cve/source-http';

import type { ConnectorInfo } from '../api/tokens.js';
import type { Env } from '../config/env.js';
import { GithubConnector } from './github/github-connector.js';

const MINUTE_MS = 60_000;
const MB = 1024 * 1024;

/**
 * GitHub quotas (2026-11): the search API allows 10 requests per minute without a token and 30
 * with one; the core API 60 per hour without a token and 5 000 with one. One limiter per API
 * keeps each quota; `x-ratelimit-*` headers pause the client when the quota is exhausted.
 */
export function githubRateLimits(authenticated: boolean): { search: RateLimit; core: RateLimit } {
  return authenticated
    ? {
        search: { maxRequests: 25, windowMs: MINUTE_MS },
        core: { maxRequests: 4_500, windowMs: 60 * MINUTE_MS },
      }
    : {
        search: { maxRequests: 9, windowMs: MINUTE_MS },
        core: { maxRequests: 55, windowMs: 60 * MINUTE_MS },
      };
}

export interface ConnectorRegistryOptions {
  readonly logger: Logger;
  /** Replaces `fetch` (tests point the connector at a mocked API). */
  readonly fetch?: typeof fetch;
  readonly rateLimits?: { search: RateLimit; core: RateLimit };
  readonly retryBaseDelayMs?: number;
}

export interface ConnectorRegistry {
  readonly github: GithubConnector | null;
  readonly referencesEnabled: boolean;
  readonly info: readonly ConnectorInfo[];
}

/**
 * Builds the enabled connectors. The GitHub connector talks only to the configured API origin;
 * search and core requests have separate limiters but share the origin allowlist.
 */
export function createConnectorRegistry(
  env: Env,
  options: ConnectorRegistryOptions,
): ConnectorRegistry {
  const enabled = new Set(env.POC_CONNECTORS_ENABLED);
  const authenticated = env.GITHUB_TOKEN !== undefined;
  const limits = options.rateLimits ?? githubRateLimits(authenticated);
  const origin = new URL(env.GITHUB_API_URL).origin;
  let github: GithubConnector | null = null;
  if (enabled.has('github')) {
    const client = (limit: RateLimit, maxResponseBytes: number) =>
      new SourceHttpClient({
        source: 'github',
        allowedOrigins: [origin],
        rateLimiter: new SlidingWindowRateLimiter(limit),
        timeoutMs: env.SOURCE_HTTP_TIMEOUT_MS,
        maxResponseBytes,
        userAgent: env.SOURCE_HTTP_USER_AGENT,
        logger: options.logger.child({ connector: 'github' }),
        retry: {
          ...DEFAULT_RETRY_POLICY,
          maxAttempts: env.SOURCE_HTTP_MAX_ATTEMPTS,
          ...(options.retryBaseDelayMs === undefined
            ? {}
            : { baseDelayMs: options.retryBaseDelayMs }),
        },
        quotaResetFromHeaders: githubQuotaReset,
        ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      });
    github = new GithubConnector({
      searchClient: client(limits.search, 10 * MB),
      coreClient: client(limits.core, 16 * MB),
      apiUrl: env.GITHUB_API_URL,
      token: env.GITHUB_TOKEN,
      searchIn: env.POC_GITHUB_SEARCH_IN,
      maxSearchPages: env.POC_GITHUB_MAX_SEARCH_PAGES,
    });
  }
  return {
    github,
    referencesEnabled: enabled.has('cve-references'),
    info: [
      {
        connector: 'github',
        enabled: github !== null,
        allowedOrigins: [origin],
        authentication: { mode: 'optional', configured: authenticated },
        schedule: github === null ? null : env.POC_GITHUB_RECENT_CRON,
      },
      {
        connector: 'cve-references',
        enabled: enabled.has('cve-references'),
        allowedOrigins: [],
        authentication: { mode: 'none', configured: false },
        schedule: null,
      },
    ],
  };
}
