import { describe, expect, it } from 'vitest';

import { createDomainEvent } from './domain-event.js';
import { CORRELATION_ID_HEADER, EVENT_VERSION_HEADER, toAmqpMessage } from './publisher.js';

describe('createDomainEvent', () => {
  it('fills identifiers and timestamps', () => {
    const event = createDomainEvent({
      eventType: 'cve.record.created',
      producer: 'cve-service',
      payload: { cveId: 'CVE-2026-0001' },
      correlationId: 'req-1',
    });
    expect(event.eventId).toMatch(/^[0-9a-f-]{36}$/);
    expect(event.eventVersion).toBe(1);
    expect(Date.parse(event.occurredAt)).not.toBeNaN();
    expect(event.correlationId).toBe('req-1');
  });

  it('rejects invalid event types', () => {
    expect(() =>
      createDomainEvent({ eventType: 'CveCreated', producer: 'cve-service', payload: {} }),
    ).toThrow();
  });
});

describe('toAmqpMessage', () => {
  it('maps the envelope onto persistent AMQP properties', () => {
    const event = createDomainEvent({
      eventType: 'cve.record.updated',
      eventVersion: 2,
      producer: 'cve-service',
      payload: { cveId: 'CVE-2026-0002' },
      correlationId: 'corr',
      eventId: '7d0b5b8e-4a35-4b7f-9e1b-2d7c1a9f0e11',
      occurredAt: new Date('2026-11-04T00:00:00Z'),
    });
    const message = toAmqpMessage(event);
    expect(message.routingKey).toBe('cve.record.updated');
    expect(message.properties).toMatchObject({
      persistent: true,
      mandatory: true,
      messageId: event.eventId,
      type: 'cve.record.updated',
      appId: 'cve-service',
      timestamp: 1_793_750_400,
      headers: { [EVENT_VERSION_HEADER]: 2, [CORRELATION_ID_HEADER]: 'corr' },
    });
    expect(JSON.parse(message.content.toString('utf8'))).toEqual(event);
  });
});
