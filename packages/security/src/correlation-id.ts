import { randomUUID } from 'node:crypto';

const CORRELATION_ID_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;

/** Accepts only short, log-safe identifiers so clients cannot inject content into logs. */
export function isValidCorrelationId(value: unknown): value is string {
  return typeof value === 'string' && CORRELATION_ID_PATTERN.test(value);
}

export function generateCorrelationId(): string {
  return randomUUID();
}

/** Returns the incoming correlation ID when valid, otherwise a freshly generated one. */
export function resolveCorrelationId(incoming: unknown): string {
  const candidate = Array.isArray(incoming) ? (incoming[0] as unknown) : incoming;
  return isValidCorrelationId(candidate) ? candidate : generateCorrelationId();
}
