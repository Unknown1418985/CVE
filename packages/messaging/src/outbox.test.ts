import type { DomainEventEnvelope } from '@cve/contracts';
import { createLogger } from '@cve/logger';
import { describe, expect, it } from 'vitest';

import { createDomainEvent } from './domain-event.js';
import { OutboxRelay, outboxRetryDelayMs, type OutboxRecord, type OutboxStore } from './outbox.js';

interface Row {
  record: OutboxRecord;
  publishedAt?: Date;
  nextAttemptAt: Date;
  lastError?: string;
}

/** Test double that mimics the contract of a database-backed outbox. */
class FakeOutboxStore implements OutboxStore {
  readonly rows: Row[] = [];

  add(event: DomainEventEnvelope): void {
    this.rows.push({
      record: { id: event.eventId, event, attempts: 0 },
      nextAttemptAt: new Date(0),
    });
  }

  claimDue(limit: number, now: Date): Promise<readonly OutboxRecord[]> {
    return Promise.resolve(
      this.rows
        .filter((row) => row.publishedAt === undefined && row.nextAttemptAt <= now)
        .slice(0, limit)
        .map((row) => row.record),
    );
  }

  markPublished(id: string, publishedAt: Date): Promise<void> {
    this.row(id).publishedAt = publishedAt;
    return Promise.resolve();
  }

  markFailed(id: string, error: string, nextAttemptAt: Date): Promise<void> {
    const row = this.row(id);
    row.record = { ...row.record, attempts: row.record.attempts + 1 };
    row.lastError = error;
    row.nextAttemptAt = nextAttemptAt;
    return Promise.resolve();
  }

  private row(id: string): Row {
    const row = this.rows.find((candidate) => candidate.record.id === id);
    if (!row) throw new Error(`no row ${id}`);
    return row;
  }
}

const logger = createLogger({ service: 'test', level: 'silent' });
const event = (n: number) =>
  createDomainEvent({ eventType: 'cve.record.created', producer: 'cve-service', payload: { n } });

describe('OutboxRelay', () => {
  it('publishes due events and marks them published', async () => {
    const store = new FakeOutboxStore();
    store.add(event(1));
    store.add(event(2));
    const published: DomainEventEnvelope[] = [];
    const relay = new OutboxRelay({
      store,
      logger,
      publisher: { publish: (e) => Promise.resolve(void published.push(e)) },
    });
    await expect(relay.runOnce()).resolves.toEqual({ published: 2, failed: 0 });
    expect(published.map((e) => e.payload)).toEqual([{ n: 1 }, { n: 2 }]);
    await expect(relay.runOnce()).resolves.toEqual({ published: 0, failed: 0 });
  });

  it('backs off failed publications and retries them later', async () => {
    const store = new FakeOutboxStore();
    store.add(event(1));
    let now = new Date('2026-11-04T00:00:00Z');
    let fail = true;
    const relay = new OutboxRelay({
      store,
      logger,
      baseRetryDelayMs: 1_000,
      now: () => now,
      publisher: {
        publish: () => (fail ? Promise.reject(new Error('broker down')) : Promise.resolve()),
      },
    });

    await expect(relay.runOnce()).resolves.toEqual({ published: 0, failed: 1 });
    expect(store.rows[0]?.lastError).toBe('broker down');
    expect(store.rows[0]?.nextAttemptAt.toISOString()).toBe('2026-11-04T00:00:01.000Z');

    // Not due yet.
    await expect(relay.runOnce()).resolves.toEqual({ published: 0, failed: 0 });

    now = new Date('2026-11-04T00:00:05Z');
    fail = false;
    await expect(relay.runOnce()).resolves.toEqual({ published: 1, failed: 0 });
  });
});

describe('outboxRetryDelayMs', () => {
  it('grows exponentially and is capped', () => {
    expect(outboxRetryDelayMs(0, 1_000, 60_000)).toBe(1_000);
    expect(outboxRetryDelayMs(3, 1_000, 60_000)).toBe(8_000);
    expect(outboxRetryDelayMs(20, 1_000, 60_000)).toBe(60_000);
  });
});
