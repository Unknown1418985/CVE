import { describe, expect, it } from 'vitest';

import {
  aggregateHealthStatus,
  apiErrorResponseSchema,
  BACKEND_SERVICE_NAMES,
  buildPaginationMeta,
  domainEventEnvelopeSchema,
  paginationQuerySchema,
  SERVICE_DEFAULT_PORTS,
  SERVICE_NAMES,
} from './index.js';

describe('service registry', () => {
  it('assigns a unique default port to every service', () => {
    const ports = SERVICE_NAMES.map((name) => SERVICE_DEFAULT_PORTS[name]);
    expect(new Set(ports).size).toBe(SERVICE_NAMES.length);
  });

  it('excludes the gateway from backend services', () => {
    expect(BACKEND_SERVICE_NAMES).not.toContain('api-gateway');
    expect(BACKEND_SERVICE_NAMES).toHaveLength(SERVICE_NAMES.length - 1);
  });
});

describe('pagination', () => {
  it('applies defaults and coerces query strings', () => {
    expect(paginationQuerySchema.parse({})).toEqual({ page: 1, pageSize: 25 });
    expect(paginationQuerySchema.parse({ page: '3', pageSize: '10' })).toEqual({
      page: 3,
      pageSize: 10,
    });
  });

  it('rejects page sizes above the maximum', () => {
    expect(paginationQuerySchema.safeParse({ pageSize: '1000' }).success).toBe(false);
  });

  it('computes total pages', () => {
    expect(buildPaginationMeta({ page: 1, pageSize: 10 }, 0).totalPages).toBe(0);
    expect(buildPaginationMeta({ page: 1, pageSize: 10 }, 21).totalPages).toBe(3);
  });
});

describe('health aggregation', () => {
  it('reports the worst status', () => {
    expect(aggregateHealthStatus([])).toBe('ok');
    expect(aggregateHealthStatus(['ok', 'degraded'])).toBe('degraded');
    expect(aggregateHealthStatus(['ok', 'down', 'degraded'])).toBe('down');
  });
});

describe('domain event envelope', () => {
  const valid = {
    eventId: '0b8f3f0e-6f5b-4c1e-9d55-0f7c1f6c2a11',
    eventType: 'cve.record.published',
    eventVersion: 1,
    occurredAt: '2026-01-01T00:00:00.000Z',
    producer: 'cve-service',
    payload: { cveId: 'CVE-2026-0001' },
  };

  it('accepts a well-formed event', () => {
    expect(domainEventEnvelopeSchema.safeParse(valid).success).toBe(true);
  });

  it('rejects malformed event types and unknown producers', () => {
    expect(
      domainEventEnvelopeSchema.safeParse({ ...valid, eventType: 'CvePublished' }).success,
    ).toBe(false);
    expect(domainEventEnvelopeSchema.safeParse({ ...valid, producer: 'unknown' }).success).toBe(
      false,
    );
  });
});

describe('error envelope', () => {
  it('validates the error response shape', () => {
    expect(
      apiErrorResponseSchema.safeParse({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
        timestamp: new Date().toISOString(),
      }).success,
    ).toBe(true);
  });
});
