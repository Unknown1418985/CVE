import { CORRELATION_ID_HEADER_NAME, IDEMPOTENCY_KEY_HEADER_NAME } from './constants.js';

export type CorsOriginCallback = (error: Error | null, allow?: boolean) => void;

/** Structurally compatible with the `cors` package options accepted by NestJS. */
export interface StrictCorsOptions {
  origin: (origin: string | undefined, callback: CorsOriginCallback) => void;
  credentials: boolean;
  methods: string[];
  allowedHeaders: string[];
  exposedHeaders: string[];
  maxAge: number;
}

/**
 * Builds CORS options that only allow explicitly configured origins.
 * Wildcards are rejected; requests without an Origin header (server-to-server) are allowed.
 */
export function buildCorsOptions(allowedOrigins: readonly string[]): StrictCorsOptions {
  for (const origin of allowedOrigins) {
    if (origin === '*' || origin.includes('*')) {
      throw new Error('Wildcard CORS origins are not permitted');
    }
    const parsed = new URL(origin);
    if (parsed.origin !== origin) {
      throw new Error(`CORS origin must be a bare origin without path: ${origin}`);
    }
  }
  const allowed = new Set(allowedOrigins);

  return {
    origin: (origin, callback) => {
      callback(null, origin === undefined || allowed.has(origin));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'authorization',
      'content-type',
      CORRELATION_ID_HEADER_NAME,
      IDEMPOTENCY_KEY_HEADER_NAME,
    ],
    exposedHeaders: [CORRELATION_ID_HEADER_NAME],
    maxAge: 600,
  };
}
