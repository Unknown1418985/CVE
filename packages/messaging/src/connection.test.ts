import { describe, expect, it } from 'vitest';

import { redactAmqpUrl, withHeartbeat } from './connection.js';
import { RedisProcessedEventStore } from './processed-events.js';

describe('connection helpers', () => {
  it('redacts passwords', () => {
    const redacted = redactAmqpUrl('amqp://svc:s3cret@rabbitmq:5672/cve');
    expect(redacted).not.toContain('s3cret');
    expect(redacted).toContain('svc');
    expect(redactAmqpUrl('::')).toBe('[invalid url]');
  });

  it('adds a heartbeat unless one is configured', () => {
    expect(withHeartbeat('amqp://u:p@h:5672/cve', 30)).toBe('amqp://u:p@h:5672/cve?heartbeat=30');
    expect(withHeartbeat('amqp://u:p@h/cve?heartbeat=5', 30)).toBe('amqp://u:p@h/cve?heartbeat=5');
  });
});

describe('RedisProcessedEventStore', () => {
  it('stores processed IDs under the service prefix with a TTL', async () => {
    const calls: unknown[][] = [];
    const keys = new Set<string>();
    const store = new RedisProcessedEventStore({
      keyPrefix: 'cve:cve-service:',
      ttlMs: 1_000,
      redis: {
        exists: (key) => Promise.resolve(keys.has(key) ? 1 : 0),
        set: (key, ...rest) => {
          calls.push([key, ...rest]);
          keys.add(key);
          return Promise.resolve('OK');
        },
      },
    });
    await expect(store.isProcessed('indexer', 'e1')).resolves.toBe(false);
    await store.markProcessed('indexer', 'e1');
    await expect(store.isProcessed('indexer', 'e1')).resolves.toBe(true);
    expect(calls).toEqual([['cve:cve-service:inbox:indexer:e1', '1', 'PX', 1_000]]);
  });
});
