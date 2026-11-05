import { INTELLIGENCE_SOURCES, type IntelligenceSource } from '@cve/contracts';
import type { Logger } from '@cve/logger';
import {
  DEFAULT_RETRY_POLICY,
  githubQuotaReset,
  SlidingWindowRateLimiter,
  SourceHttpClient,
  type RateLimit,
} from '@cve/source-http';

import type { Env } from '../config/env.js';
import { CisaKevAdapter } from './cisa-kev/cisa-kev.adapter.js';
import { EpssAdapter } from './epss/epss.adapter.js';
import { GithubAdvisoryAdapter } from './github/github-advisory.adapter.js';
import { MitreCveAdapter } from './mitre/mitre.adapter.js';
import { NvdAdapter } from './nvd/nvd.adapter.js';
import type { SourceAdapter } from './source-adapter.js';

const MINUTE_MS = 60_000;
const MB = 1024 * 1024;

export interface RegisteredSource {
  readonly adapter: SourceAdapter;
  readonly enabled: boolean;
  /** Cron expression of the scheduled synchronisation (UTC). */
  readonly schedule: string;
}

export interface RegistryOptions {
  readonly logger: Logger;
  /** Replaces `fetch` (tests use it to point adapters at mocked APIs). */
  readonly fetch?: typeof fetch;
  /** Overrides rate limits (tests use fast limits). */
  readonly rateLimits?: Partial<Record<IntelligenceSource, RateLimit>>;
  /** Overrides retry delays (tests). */
  readonly retryBaseDelayMs?: number;
}

/**
 * Documented quotas (2026-11):
 * - NVD: 5 requests / 30 s without an API key, 50 / 30 s with one; NVD asks clients to pause
 *   between requests, so requests are also spaced.
 * - GitHub REST: 60 requests / hour unauthenticated, 5 000 / hour with a token; the
 *   `x-ratelimit-*` headers are honoured as well.
 * - MITRE CVE Services, CISA KEV and FIRST EPSS publish no hard per-client quota; conservative,
 *   configurable limits are used.
 */
export function defaultRateLimits(env: Env): Record<IntelligenceSource, RateLimit> {
  const nvdKey = env.NVD_API_KEY !== undefined;
  return {
    nvd: { maxRequests: nvdKey ? 50 : 5, windowMs: 30_000, minIntervalMs: nvdKey ? 600 : 6_000 },
    'mitre-cve': { maxRequests: env.MITRE_CVE_REQUESTS_PER_MINUTE, windowMs: MINUTE_MS },
    'cisa-kev': { maxRequests: 10, windowMs: MINUTE_MS },
    'first-epss': { maxRequests: env.EPSS_REQUESTS_PER_MINUTE, windowMs: MINUTE_MS },
    'github-advisory':
      env.GITHUB_TOKEN === undefined
        ? { maxRequests: 60, windowMs: 60 * MINUTE_MS }
        : { maxRequests: 4_500, windowMs: 60 * MINUTE_MS },
  };
}

function origin(url: string): string {
  return new URL(url).origin;
}

/** Builds one independent adapter (own HTTP client, limiter and credentials) per source. */
export function createSourceRegistry(
  env: Env,
  options: RegistryOptions,
): ReadonlyMap<IntelligenceSource, RegisteredSource> {
  const limits = { ...defaultRateLimits(env), ...options.rateLimits };
  const client = (
    source: IntelligenceSource,
    urls: readonly string[],
    extra: {
      maxResponseBytes: number;
      retryableStatuses?: readonly number[];
      quotaResetFromHeaders?: (headers: Headers) => number | undefined;
    },
  ) =>
    new SourceHttpClient({
      source,
      allowedOrigins: urls.map(origin),
      rateLimiter: new SlidingWindowRateLimiter(limits[source]),
      timeoutMs: env.SOURCE_HTTP_TIMEOUT_MS,
      maxResponseBytes: extra.maxResponseBytes,
      userAgent: env.SOURCE_HTTP_USER_AGENT,
      logger: options.logger.child({ component: 'source-http', source }),
      retry: {
        ...DEFAULT_RETRY_POLICY,
        maxAttempts: env.SOURCE_HTTP_MAX_ATTEMPTS,
        ...(options.retryBaseDelayMs === undefined
          ? {}
          : { baseDelayMs: options.retryBaseDelayMs, maxDelayMs: options.retryBaseDelayMs * 8 }),
      },
      ...(extra.retryableStatuses === undefined
        ? {}
        : { retryableStatuses: extra.retryableStatuses }),
      ...(extra.quotaResetFromHeaders === undefined
        ? {}
        : { quotaResetFromHeaders: extra.quotaResetFromHeaders }),
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    });

  const entries: [IntelligenceSource, RegisteredSource][] = [
    [
      'nvd',
      {
        enabled: env.NVD_ENABLED,
        schedule: env.NVD_SYNC_CRON,
        adapter: new NvdAdapter({
          // NVD answers 403 when the rolling quota is exceeded; it is retried with backoff.
          client: client('nvd', [env.NVD_API_URL], {
            maxResponseBytes: 64 * MB,
            retryableStatuses: [403, 408, 429, 500, 502, 503, 504],
          }),
          baseUrl: env.NVD_API_URL,
          apiKey: env.NVD_API_KEY,
          pageSize: env.NVD_PAGE_SIZE,
          initialSyncFrom: env.NVD_INITIAL_SYNC_FROM,
        }),
      },
    ],
    [
      'mitre-cve',
      {
        enabled: env.MITRE_CVE_ENABLED,
        schedule: env.MITRE_CVE_SYNC_CRON,
        adapter: new MitreCveAdapter({
          client: client('mitre-cve', [env.MITRE_CVE_API_URL, env.MITRE_CVE_DELTA_LOG_URL], {
            maxResponseBytes: 128 * MB,
          }),
          apiUrl: env.MITRE_CVE_API_URL,
          deltaLogUrl: env.MITRE_CVE_DELTA_LOG_URL,
          initialLookbackMs: env.MITRE_CVE_INITIAL_LOOKBACK_HOURS * 60 * MINUTE_MS,
        }),
      },
    ],
    [
      'cisa-kev',
      {
        enabled: env.CISA_KEV_ENABLED,
        schedule: env.CISA_KEV_SYNC_CRON,
        adapter: new CisaKevAdapter({
          client: client('cisa-kev', [env.CISA_KEV_FEED_URL], { maxResponseBytes: 32 * MB }),
          feedUrl: env.CISA_KEV_FEED_URL,
        }),
      },
    ],
    [
      'first-epss',
      {
        enabled: env.EPSS_ENABLED,
        schedule: env.EPSS_SYNC_CRON,
        adapter: new EpssAdapter({
          client: client('first-epss', [env.EPSS_API_URL], { maxResponseBytes: 32 * MB }),
          baseUrl: env.EPSS_API_URL,
          pageSize: env.EPSS_PAGE_SIZE,
          maxBackfillDays: env.EPSS_MAX_BACKFILL_DAYS,
        }),
      },
    ],
    [
      'github-advisory',
      {
        enabled: env.GITHUB_ADVISORY_ENABLED,
        schedule: env.GITHUB_ADVISORY_SYNC_CRON,
        adapter: new GithubAdvisoryAdapter({
          client: client('github-advisory', [env.GITHUB_API_URL], {
            maxResponseBytes: 32 * MB,
            quotaResetFromHeaders: githubQuotaReset,
          }),
          apiUrl: env.GITHUB_API_URL,
          token: env.GITHUB_TOKEN,
          pageSize: 100,
          initialLookbackMs: env.GITHUB_ADVISORY_INITIAL_LOOKBACK_DAYS * 24 * 60 * MINUTE_MS,
        }),
      },
    ],
  ];
  // Keep the catalog order stable for the API.
  const map = new Map(entries);
  return new Map(
    INTELLIGENCE_SOURCES.map((source) => {
      const entry = map.get(source);
      if (entry === undefined) throw new Error(`No adapter registered for ${source}`);
      return [source, entry];
    }),
  );
}

export function enabledAdapters(
  registry: ReadonlyMap<IntelligenceSource, RegisteredSource>,
): ReadonlyMap<IntelligenceSource, SourceAdapter> {
  return new Map(
    [...registry]
      .filter(([, entry]) => entry.enabled)
      .map(([source, entry]) => [source, entry.adapter]),
  );
}
