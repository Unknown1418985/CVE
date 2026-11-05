import type { DownloadErrorCode, DownloadHop } from '@cve/contracts';

/** Codes that must never be retried: the source or the content violates policy. */
const POLICY_CODES = new Set<DownloadErrorCode>([
  'source-disabled',
  'url-not-allowed',
  'host-not-allowed',
  'address-blocked',
  'too-many-redirects',
  'invalid-redirect',
  'unsupported-encoding',
  'content-type-not-allowed',
  'file-type-not-allowed',
  'size-limit-exceeded',
  'empty-response',
]);

export function isPolicyViolation(code: DownloadErrorCode): boolean {
  return POLICY_CODES.has(code);
}

/** A failed download attempt, with what was observed before it failed (provenance). */
export class DownloadError extends Error {
  readonly hops: DownloadHop[];
  readonly httpStatus: number | null;
  readonly bytesReceived: number;

  constructor(
    readonly code: DownloadErrorCode,
    message: string,
    readonly retryable: boolean,
    details: { hops?: DownloadHop[]; httpStatus?: number | null; bytesReceived?: number } = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'DownloadError';
    this.hops = details.hops ?? [];
    this.httpStatus = details.httpStatus ?? null;
    this.bytesReceived = details.bytesReceived ?? 0;
  }

  /** Policy violations are rejected; anything else that cannot be retried failed. */
  get outcome(): 'rejected' | 'failed' {
    return isPolicyViolation(this.code) ? 'rejected' : 'failed';
  }
}
