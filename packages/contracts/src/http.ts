/** Every public endpoint is versioned under this prefix (no leading slash). */
export const API_PREFIX = 'api/v1';

/** Request/response header that carries the correlation identifier. */
export const CORRELATION_ID_HEADER = 'x-correlation-id';

/** Header used by clients to make critical write operations idempotent. */
export const IDEMPOTENCY_KEY_HEADER = 'idempotency-key';
