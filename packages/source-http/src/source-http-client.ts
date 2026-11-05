import type { z } from 'zod';

import type { Logger } from '@cve/logger';

import { abortReason, sleep } from './abortable.js';
import {
  DisallowedUrlError,
  SourceHttpError,
  SourceRequestError,
  SourceResponseError,
  SourceTimeoutError,
} from './errors.js';
import type { SlidingWindowRateLimiter } from './rate-limiter.js';

export interface RetryPolicy {
  /** Total attempts per request, including the first. */
  readonly maxAttempts: number;
  /** Exponential backoff base: attempt n waits up to base · 2^(n-1) (full jitter). */
  readonly baseDelayMs: number;
  readonly maxDelayMs: number;
  /**
   * Longest `Retry-After` / quota reset the client waits for inside a run. Longer delays fail
   * the request as retryable, so the job is retried later by BullMQ instead of blocking a worker.
   */
  readonly maxRetryAfterMs: number;
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 4,
  baseDelayMs: 1_000,
  maxDelayMs: 30_000,
  maxRetryAfterMs: 5 * 60_000,
};

const DEFAULT_RETRYABLE_STATUSES = [408, 425, 429, 500, 502, 503, 504];
const MAX_REDIRECTS = 3;

export interface SourceHttpClientOptions {
  /** Source name used in logs, e.g. `nvd` or `github`. */
  readonly source: string;
  /**
   * Origins (`https://host[:port]`) requests may go to. Pagination links, redirects and
   * configured URLs outside this list are refused (SSRF protection).
   */
  readonly allowedOrigins: readonly string[];
  readonly rateLimiter: SlidingWindowRateLimiter;
  /** Budget for one request: connection, headers and the complete body. */
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
  readonly userAgent: string;
  readonly logger: Logger;
  readonly retry?: RetryPolicy;
  /** HTTP statuses that are retried (default 408, 425, 429 and 5xx gateway errors). */
  readonly retryableStatuses?: readonly number[];
  /** Sent with every request, e.g. credentials. Never logged. */
  readonly headers?: Readonly<Record<string, string>>;
  /**
   * Reads a quota reset from response headers (epoch ms until which no request may be sent),
   * e.g. GitHub's `x-ratelimit-remaining: 0` + `x-ratelimit-reset`.
   */
  readonly quotaResetFromHeaders?: (headers: Headers, now: number) => number | undefined;
  readonly fetch?: typeof fetch;
  readonly random?: () => number;
  readonly now?: () => number;
}

/** Counts the HTTP requests (including retries) made on behalf of one run. */
export interface RequestMeter {
  requests: number;
}

export interface RequestOptions {
  readonly signal?: AbortSignal;
  readonly headers?: Readonly<Record<string, string>>;
  /** Accepted media types (default `application/json`). */
  readonly accept?: readonly string[];
  /** Return `{ notModified: true }` for `304` (conditional requests). */
  readonly allowNotModified?: boolean;
  readonly meter?: RequestMeter;
}

export interface SourceResponse<T> {
  readonly notModified: false;
  readonly status: number;
  readonly url: string;
  readonly headers: Headers;
  readonly body: T;
}

export interface NotModifiedResponse {
  readonly notModified: true;
  readonly status: 304;
  readonly url: string;
  readonly headers: Headers;
}

/** Parses `Retry-After` (seconds or an HTTP date) into a delay in milliseconds. */
export function parseRetryAfter(value: string | null, now: number): number | undefined {
  if (value === null) return undefined;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed) * 1_000;
  const date = Date.parse(trimmed);
  return Number.isNaN(date) ? undefined : Math.max(0, date - now);
}

/** Exponential backoff with full jitter for attempt `attempt` (1 = first retry). */
export function backoffDelayMs(attempt: number, policy: RetryPolicy, random: () => number): number {
  const ceiling = Math.min(policy.maxDelayMs, policy.baseDelayMs * 2 ** Math.max(0, attempt - 1));
  return Math.round(ceiling * random());
}

function mediaType(contentType: string | null): string {
  return (contentType ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
}

/** URL for logs: origin and path only (query strings can carry filters, never credentials). */
export function loggableUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return '[invalid url]';
  }
}

/**
 * HTTP client for one external source: allowlisted origins, rate limiting, per-request
 * timeouts, response size limits, content-type checks, schema validation, and retries with
 * exponential backoff that honour `Retry-After`.
 */
export class SourceHttpClient {
  private readonly retry: RetryPolicy;
  private readonly retryableStatuses: ReadonlySet<number>;
  private readonly allowedOrigins: ReadonlySet<string>;
  private readonly fetchImpl: typeof fetch;
  private readonly random: () => number;
  private readonly now: () => number;

  constructor(private readonly options: SourceHttpClientOptions) {
    this.retry = options.retry ?? DEFAULT_RETRY_POLICY;
    this.retryableStatuses = new Set(options.retryableStatuses ?? DEFAULT_RETRYABLE_STATUSES);
    this.allowedOrigins = new Set(options.allowedOrigins.map((origin) => new URL(origin).origin));
    this.fetchImpl = options.fetch ?? fetch;
    this.random = options.random ?? Math.random;
    this.now = options.now ?? Date.now;
    if (this.allowedOrigins.size === 0) throw new Error('allowedOrigins must not be empty');
  }

  get rateLimit() {
    return this.options.rateLimiter.limit;
  }

  /** Throws unless `url` is an absolute URL on an allowed origin without credentials. */
  assertAllowed(url: string): URL {
    if (!URL.canParse(url)) throw new DisallowedUrlError(url, 'not an absolute URL');
    const parsed = new URL(url);
    if (parsed.username !== '' || parsed.password !== '') {
      throw new DisallowedUrlError(loggableUrl(url), 'URLs must not contain credentials');
    }
    if (!this.allowedOrigins.has(parsed.origin)) {
      throw new DisallowedUrlError(loggableUrl(url), 'origin is not allowlisted for this source');
    }
    return parsed;
  }

  async getJson<T>(
    url: string,
    schema: z.ZodType<T>,
    options: RequestOptions & { allowNotModified: true },
  ): Promise<SourceResponse<T> | NotModifiedResponse>;
  async getJson<T>(
    url: string,
    schema: z.ZodType<T>,
    options?: RequestOptions,
  ): Promise<SourceResponse<T>>;
  async getJson<T>(
    url: string,
    schema: z.ZodType<T>,
    options: RequestOptions = {},
  ): Promise<SourceResponse<T> | NotModifiedResponse> {
    const response = await this.request(url, options);
    if (response.notModified) return response;
    let parsed: unknown;
    try {
      parsed = JSON.parse(response.body);
    } catch (error) {
      throw new SourceResponseError(
        `Invalid JSON from ${loggableUrl(response.url)}`,
        response.url,
        {
          cause: error,
        },
      );
    }
    const result = schema.safeParse(parsed);
    if (!result.success) {
      const issue = result.error.issues[0];
      throw new SourceResponseError(
        `Unexpected response format from ${loggableUrl(response.url)}: ${issue?.path.join('.') ?? ''} ${issue?.message ?? ''}`.trim(),
        response.url,
      );
    }
    return { ...response, body: result.data };
  }

  /** Sends a GET request with retries and returns the body as text. */
  async request(
    url: string,
    options: RequestOptions = {},
  ): Promise<SourceResponse<string> | NotModifiedResponse> {
    this.assertAllowed(url);
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.attempt(url, options);
      } catch (error) {
        if (options.signal?.aborted) throw abortReason(options.signal);
        const failure =
          error instanceof SourceRequestError
            ? error
            : new SourceRequestError(
                `Request to ${loggableUrl(url)} failed: ${error instanceof Error ? error.message : String(error)}`,
                true,
                url,
                { cause: error },
              );
        if (!failure.retryable || attempt >= this.retry.maxAttempts) throw failure;
        const requested = failure instanceof SourceHttpError ? failure.retryAfterMs : undefined;
        if (requested !== undefined && requested > this.retry.maxRetryAfterMs) throw failure;
        const delay = Math.max(requested ?? 0, backoffDelayMs(attempt, this.retry, this.random));
        this.options.logger.warn(
          {
            source: this.options.source,
            url: loggableUrl(url),
            attempt,
            maxAttempts: this.retry.maxAttempts,
            retryInMs: delay,
            err: failure,
          },
          'source request failed, retrying',
        );
        await sleep(delay, options.signal);
      }
    }
  }

  private async attempt(
    initialUrl: string,
    options: RequestOptions,
  ): Promise<SourceResponse<string> | NotModifiedResponse> {
    const timeout = new AbortController();
    const signal =
      options.signal === undefined
        ? timeout.signal
        : AbortSignal.any([options.signal, timeout.signal]);
    const timer = setTimeout(() => {
      timeout.abort(new SourceTimeoutError(loggableUrl(initialUrl), this.options.timeoutMs));
    }, this.options.timeoutMs);
    try {
      let url = initialUrl;
      for (let redirects = 0; ; redirects += 1) {
        await this.options.rateLimiter.acquire(signal);
        if (options.meter) options.meter.requests += 1;
        const started = this.now();
        let response: Response;
        try {
          response = await this.fetchImpl(url, {
            method: 'GET',
            redirect: 'manual',
            signal,
            headers: {
              accept: (options.accept ?? ['application/json']).join(', '),
              'user-agent': this.options.userAgent,
              ...this.options.headers,
              ...options.headers,
            },
          });
        } catch (error) {
          if (timeout.signal.aborted) throw abortReason(timeout.signal);
          throw error;
        }
        this.options.logger.debug(
          {
            source: this.options.source,
            url: loggableUrl(url),
            status: response.status,
            durationMs: this.now() - started,
          },
          'source response',
        );
        const quotaReset = this.options.quotaResetFromHeaders?.(response.headers, this.now());
        if (quotaReset !== undefined) this.options.rateLimiter.pauseUntil(quotaReset);

        if (response.status >= 300 && response.status < 400 && response.status !== 304) {
          await response.body?.cancel();
          const location = response.headers.get('location');
          if (location === null || redirects >= MAX_REDIRECTS) {
            throw new SourceResponseError(`Unfollowable redirect from ${loggableUrl(url)}`, url);
          }
          url = this.assertAllowed(new URL(location, url).href).href;
          continue;
        }
        if (response.status === 304 && options.allowNotModified === true) {
          await response.body?.cancel();
          return { notModified: true, status: 304, url, headers: response.headers };
        }
        if (response.status < 200 || response.status >= 300) {
          await response.body?.cancel();
          const requestedDelay = parseRetryAfter(response.headers.get('retry-after'), this.now());
          const retryAfter =
            requestedDelay ??
            (quotaReset === undefined ? undefined : Math.max(0, quotaReset - this.now()));
          // 403 with Retry-After is how some APIs (GitHub secondary limits) signal throttling.
          const throttled =
            quotaReset !== undefined || (response.status === 403 && requestedDelay !== undefined);
          throw new SourceHttpError(
            response.status,
            loggableUrl(url),
            this.retryableStatuses.has(response.status) || throttled,
            retryAfter,
          );
        }
        const accepted = options.accept ?? ['application/json'];
        const type = mediaType(response.headers.get('content-type'));
        if (!accepted.includes(type)) {
          await response.body?.cancel();
          throw new SourceResponseError(
            `Unexpected content type "${type}" from ${loggableUrl(url)}`,
            url,
          );
        }
        const body = await this.readBody(response, url, timeout.signal);
        return {
          notModified: false,
          status: response.status,
          url,
          headers: response.headers,
          body,
        };
      }
    } finally {
      clearTimeout(timer);
    }
  }

  private async readBody(response: Response, url: string, timeout: AbortSignal): Promise<string> {
    const limit = this.options.maxResponseBytes;
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > limit) {
      await response.body?.cancel();
      throw new SourceResponseError(
        `Response from ${loggableUrl(url)} exceeds ${limit} bytes`,
        url,
      );
    }
    if (response.body === null) return '';
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      // Leaving the loop early (the throw below) cancels the stream.
      for await (const value of response.body as AsyncIterable<Uint8Array>) {
        size += value.byteLength;
        if (size > limit) {
          throw new SourceResponseError(
            `Response from ${loggableUrl(url)} exceeds ${limit} bytes`,
            url,
          );
        }
        chunks.push(value);
      }
    } catch (error) {
      if (timeout.aborted) throw abortReason(timeout);
      throw error;
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(Buffer.concat(chunks));
  }
}
