/** Base class of every failure talking to an external source. */
export class SourceRequestError extends Error {
  constructor(
    message: string,
    /** Whether repeating the request (or the run) later can succeed. */
    readonly retryable: boolean,
    readonly url: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'SourceRequestError';
  }
}

/** The source answered with an HTTP error status. */
export class SourceHttpError extends SourceRequestError {
  constructor(
    readonly status: number,
    url: string,
    retryable: boolean,
    /** Delay requested by the source (`Retry-After` or a rate-limit reset), if any. */
    readonly retryAfterMs: number | undefined,
  ) {
    super(`HTTP ${status} from ${url}`, retryable, url);
    this.name = 'SourceHttpError';
  }
}

export class SourceTimeoutError extends SourceRequestError {
  constructor(url: string, timeoutMs: number) {
    super(`No complete response from ${url} within ${timeoutMs}ms`, true, url);
    this.name = 'SourceTimeoutError';
  }
}

/** The response does not have the expected size, type or shape. Not retryable. */
export class SourceResponseError extends SourceRequestError {
  constructor(message: string, url: string, options?: { cause?: unknown }) {
    super(message, false, url, options);
    this.name = 'SourceResponseError';
  }
}

/** A URL outside the source's allowlist (configuration error, redirect or pagination link). */
export class DisallowedUrlError extends SourceRequestError {
  constructor(url: string, reason: string) {
    super(`Refusing to request ${url}: ${reason}`, false, url);
    this.name = 'DisallowedUrlError';
  }
}

/**
 * Whether a failed run should be retried. Errors that declare `retryable` decide themselves;
 * anything else (database outage, unexpected exception) is retried within the job's attempts.
 */
export function isRetryable(error: unknown): boolean {
  if (error instanceof SourceRequestError) return error.retryable;
  if (error instanceof Error && 'retryable' in error && typeof error.retryable === 'boolean') {
    return error.retryable;
  }
  return true;
}
