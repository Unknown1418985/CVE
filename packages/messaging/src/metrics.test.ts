import { createLogger } from '@cve/logger';
import { platformRegistry } from '@cve/metrics';
import { describe, expect, it } from 'vitest';

import { createDomainEvent } from './domain-event.js';
import { recordConsumed } from './metrics.js';
import { OutboxRelay, type OutboxStore } from './outbox.js';

const logger = createLogger({ service: 'test', level: 'silent' });

async function metric(name: string): Promise<string> {
  return platformRegistry.getSingleMetricAsString(name);
}

describe('messaging metrics', () => {
  it('counts consumed events by queue, type and outcome with bounded labels', async () => {
    recordConsumed('asset-service.cve-facts', 'cve.record.created', 'processed');
    recordConsumed('asset-service.cve-facts', 'not a "valid" type', 'dead_lettered');
    const text = await metric('messaging_events_consumed_total');
    expect(text).toContain(
      'messaging_events_consumed_total{queue="asset-service.cve-facts",event_type="cve.record.created",outcome="processed"} 1',
    );
    expect(text).toContain('event_type="other",outcome="dead_lettered"} 1');
  });

  it('counts relayed outbox records and reports the backlog while the relay runs', async () => {
    const event = createDomainEvent({
      eventType: 'cve.record.created',
      producer: 'cve-service',
      payload: {},
    });
    let claimed = false;
    const store: OutboxStore = {
      claimDue: () => {
        if (claimed) return Promise.resolve([]);
        claimed = true;
        return Promise.resolve([{ id: 'a', event, attempts: 0 }]);
      },
      markPublished: () => Promise.resolve(),
      markFailed: () => Promise.resolve(),
      backlog: () => Promise.resolve({ pending: 7, oldestPendingAgeSeconds: 42 }),
    };
    const relay = new OutboxRelay({
      store,
      logger,
      pollIntervalMs: 60_000,
      publisher: { publish: () => Promise.resolve() },
    });
    await relay.runOnce();
    expect(await metric('outbox_events_relayed_total')).toContain(
      'outbox_events_relayed_total{outcome="published"} 1',
    );

    relay.start();
    try {
      expect(await metric('outbox_pending_events')).toContain('outbox_pending_events 7');
      await new Promise((resolve) => setTimeout(resolve, 1_100));
      expect(await metric('outbox_oldest_pending_age_seconds')).toContain(
        'outbox_oldest_pending_age_seconds 42',
      );
    } finally {
      await relay.stop();
    }
  });

  it('does not fail the scrape when the backlog query fails', async () => {
    const relay = new OutboxRelay({
      store: {
        claimDue: () => Promise.resolve([]),
        markPublished: () => Promise.resolve(),
        markFailed: () => Promise.resolve(),
        backlog: () => Promise.reject(new Error('database down')),
      },
      logger,
      pollIntervalMs: 60_000,
      publisher: { publish: () => Promise.resolve() },
    });
    await new Promise((resolve) => setTimeout(resolve, 1_100));
    relay.start();
    try {
      await expect(platformRegistry.metrics()).resolves.toContain('outbox_pending_events');
    } finally {
      await relay.stop();
    }
  });
});
