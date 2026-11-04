/** Default API rate limit applied at the gateway (per client IP). */
export const DEFAULT_RATE_LIMIT = {
  /** Window length in milliseconds. */
  ttlMs: 60_000,
  /** Maximum requests per window. */
  limit: 300,
} as const;
