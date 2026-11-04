import type { ConsumeMessage } from 'amqplib';
import { describe, expect, it } from 'vitest';

import { ATTEMPT_HEADER, decideFailureAction, readAttempt } from './consumer.js';
import { NonRetryableEventError } from './errors.js';
import { consumerTopology } from './topology.js';

const topology = consumerTopology('notification-service', 'alert-dispatcher', 2);

describe('decideFailureAction', () => {
  it('schedules retries through the delay queues in order', () => {
    expect(decideFailureAction(topology, 1, new Error('boom'))).toEqual({
      kind: 'retry',
      retryQueue: 'notification-service.alert-dispatcher.retry.1',
      nextAttempt: 2,
    });
    expect(decideFailureAction(topology, 2, new Error('boom'))).toMatchObject({
      retryQueue: 'notification-service.alert-dispatcher.retry.2',
      nextAttempt: 3,
    });
  });

  it('dead-letters after the last retry', () => {
    expect(decideFailureAction(topology, 3, new Error('boom'))).toEqual({
      kind: 'dead-letter',
      reason: 'retries exhausted after 3 attempt(s)',
    });
  });

  it('dead-letters non-retryable errors immediately', () => {
    expect(decideFailureAction(topology, 1, new NonRetryableEventError('bad'))).toMatchObject({
      kind: 'dead-letter',
    });
  });
});

describe('readAttempt', () => {
  const message = (headers: Record<string, unknown> | undefined) =>
    ({ properties: { headers } }) as unknown as ConsumeMessage;

  it('defaults to the first attempt', () => {
    expect(readAttempt(message(undefined))).toBe(1);
    expect(readAttempt(message({ [ATTEMPT_HEADER]: 'garbage' }))).toBe(1);
    expect(readAttempt(message({ [ATTEMPT_HEADER]: -4 }))).toBe(1);
  });

  it('reads numeric headers', () => {
    expect(readAttempt(message({ [ATTEMPT_HEADER]: 3 }))).toBe(3);
    expect(readAttempt(message({ [ATTEMPT_HEADER]: '2' }))).toBe(2);
  });
});
