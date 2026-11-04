/** Default API rate limit applied at the gateway (per authenticated user, otherwise per client IP). */
export const DEFAULT_RATE_LIMIT = {
  /** Window length in milliseconds. */
  ttlMs: 60_000,
  /** Maximum requests per window. */
  limit: 300,
  /** Maximum requests per window to authentication endpoints (logout, session changes). */
  authLimit: 20,
} as const;
