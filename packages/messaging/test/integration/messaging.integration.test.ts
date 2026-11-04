import { randomUUID } from 'node:crypto';

import type { DomainEventEnvelope } from '@cve/contracts';
import { createLogger } from '@cve/logger';
import { integrationHost, requireEnv, serviceRabbitMqUrl } from '@cve/testing/integration';
import { connect, type ChannelModel } from 'amqplib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  EventConsumer,
  EventPublisher,
  NonRetryableEventError,
  RabbitMqConnection,
  consumerTopology,
  createDomainEvent,
  createRabbitMqHealthIndicator,
  type DomainEvent,
  type ProcessedEventStore,
} from '../../src/index.js';

const logger = createLogger({ service: 'messaging-integration', level: 'silent' });
const payloadSchema = z.object({ cveId: z.string().regex(/^CVE-\d{4}-\d{4,}$/) });
type Payload = z.infer<typeof payloadSchema>;

/** Unique names per run so repeated runs never share queues. */
const run = randomUUID()
  .slice(0, 8)
  .replace(/[0-9]/g, (digit) => 'ghijklmnop'.charAt(Number(digit)));
const eventType = (action: string) => `itest-${run}.record.${action}`;

function waitFor<T>(predicate: () => T | undefined, timeoutMs = 15_000): Promise<T> {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      const value = predicate();
      if (value !== undefined) {
        resolve(value);
      } else if (Date.now() - started > timeoutMs) {
        reject(new Error('condition not met in time'));
      } else {
        setTimeout(tick, 50);
      }
    };
    tick();
  });
}

class MemoryProcessedEvents implements ProcessedEventStore {
  private readonly ids = new Set<string>();
  isProcessed(consumer: string, eventId: string) {
    return Promise.resolve(this.ids.has(`${consumer}:${eventId}`));
  }
  markProcessed(consumer: string, eventId: string) {
    this.ids.add(`${consumer}:${eventId}`);
    return Promise.resolve();
  }
}

describe('RabbitMQ messaging (live broker, least-privilege service users)', () => {
  const connection = new RabbitMqConnection({
    url: serviceRabbitMqUrl('cve-service'),
    connectionName: `cve-service-itest-${run}`,
    logger,
    initialMaxRetries: 2,
  });
  const publisher = new EventPublisher({ connection, producer: 'cve-service', logger });
  const consumer = new EventConsumer({
    connection,
    service: 'cve-service',
    logger,
    processedEvents: new MemoryProcessedEvents(),
  });
  const declaredQueues: string[] = [];
  let inspector: ChannelModel;

  const publish = (
    action: string,
    payload: unknown,
    overrides: Partial<DomainEventEnvelope> = {},
  ) =>
    publisher.publish({
      ...createDomainEvent({
        eventType: eventType(action),
        producer: 'cve-service',
        payload,
        correlationId: `corr-${run}`,
      }),
      ...overrides,
    });

  async function messageCount(queue: string): Promise<number> {
    const channel = await inspector.createChannel();
    try {
      return (await channel.checkQueue(queue)).messageCount;
    } finally {
      await channel.close();
    }
  }

  beforeAll(async () => {
    await connection.connect();
    await publisher.start();
    inspector = await connect(serviceRabbitMqUrl('cve-service'));
  });

  afterAll(async () => {
    await consumer.close();
    await publisher.close();
    const channel = await inspector.createChannel();
    for (const queue of declaredQueues) await channel.deleteQueue(queue);
    await channel.close();
    await inspector.close();
    await connection.close();
  });

  async function subscribe(
    name: string,
    action: string,
    handle: (event: DomainEvent<Payload>, attempt: number) => Promise<void>,
    retryDelaysMs: number[] = [300],
  ) {
    const topology = await consumer.subscribe({
      consumer: `itest-${run}-${name}`,
      eventTypes: [eventType(action)],
      payloadSchema,
      retryDelaysMs,
      handle: (event, context) => handle(event, context.attempt),
    });
    declaredQueues.push(topology.queue, topology.deadLetterQueue, ...topology.retryQueues);
    return topology;
  }

  it('reports a healthy connection', async () => {
    await expect(createRabbitMqHealthIndicator(connection).check(1_000)).resolves.toMatchObject({
      status: 'ok',
    });
  });

  it('delivers published events with validated payloads and correlation IDs', async () => {
    const received: DomainEvent<Payload>[] = [];
    await subscribe('roundtrip', 'created', (event) => {
      received.push(event);
      return Promise.resolve();
    });
    await publish('created', { cveId: 'CVE-2026-0001' });
    const event = await waitFor(() => received[0]);
    expect(event.payload).toEqual({ cveId: 'CVE-2026-0001' });
    expect(event.producer).toBe('cve-service');
    expect(event.correlationId).toBe(`corr-${run}`);
  });

  it('retries failed handlers through the delay queue', async () => {
    const attempts: number[] = [];
    await subscribe('retry', 'retried', (_event, attempt) => {
      attempts.push(attempt);
      return attempt === 1 ? Promise.reject(new Error('transient')) : Promise.resolve();
    });
    await publish('retried', { cveId: 'CVE-2026-0002' });
    await waitFor(() => (attempts.length >= 2 ? true : undefined));
    expect(attempts).toEqual([1, 2]);
  });

  it('dead-letters events after the last retry, and non-retryable or invalid events immediately', async () => {
    let attempts = 0;
    const exhausted = await subscribe('exhausted', 'exhausted', () => {
      attempts += 1;
      return Promise.reject(new Error('always fails'));
    });
    await publish('exhausted', { cveId: 'CVE-2026-0003' });
    await waitFor(() => (attempts >= 2 ? true : undefined));
    await expect.poll(() => messageCount(exhausted.deadLetterQueue), { timeout: 10_000 }).toBe(1);
    expect(attempts).toBe(2);

    let rejected = 0;
    const permanent = await subscribe('permanent', 'permanent', () => {
      rejected += 1;
      return Promise.reject(new NonRetryableEventError('business rule'));
    });
    await publish('permanent', { cveId: 'CVE-2026-0004' });
    await expect.poll(() => messageCount(permanent.deadLetterQueue), { timeout: 10_000 }).toBe(1);
    expect(rejected).toBe(1);

    let handled = 0;
    const invalid = await subscribe('invalid', 'invalid', () => {
      handled += 1;
      return Promise.resolve();
    });
    await publish('invalid', { cveId: 'not-a-cve' });
    await expect.poll(() => messageCount(invalid.deadLetterQueue), { timeout: 10_000 }).toBe(1);
    expect(handled).toBe(0);
  });

  it('suppresses duplicate deliveries of the same event ID', async () => {
    let handled = 0;
    await subscribe('dedup', 'deduplicated', () => {
      handled += 1;
      return Promise.resolve();
    });
    const event = createDomainEvent({
      eventType: eventType('deduplicated'),
      producer: 'cve-service',
      payload: { cveId: 'CVE-2026-0005' },
    });
    await publisher.publish(event);
    await publisher.publish(event);
    await waitFor(() => (handled >= 1 ? true : undefined));
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    expect(handled).toBe(1);
  });

  it('rejects events claiming another producer', async () => {
    await expect(
      publisher.publish(
        createDomainEvent({
          eventType: eventType('spoofed'),
          producer: 'poc-service',
          payload: {},
        }),
      ),
    ).rejects.toThrow(/does not match publisher/);
  });

  it('recovers consumers after the broker drops the connection', async () => {
    const received: string[] = [];
    await subscribe('recovery', 'recovered', (event) => {
      received.push(event.payload.cveId);
      return Promise.resolve();
    });
    const admin = requireEnv('RABBITMQ_ADMIN_USER');
    const password = requireEnv('RABBITMQ_ADMIN_PASSWORD');
    const auth = `Basic ${Buffer.from(`${admin}:${password}`).toString('base64')}`;
    const base = `http://${integrationHost()}:15672/api`;
    // The management API lists new connections after its next statistics interval.
    const findTarget = async () => {
      const connections = (await (
        await fetch(`${base}/connections`, { headers: { authorization: auth } })
      ).json()) as {
        name: string;
        client_properties?: { connection_name?: string };
      }[];
      return connections.find(
        (c) => c.client_properties?.connection_name === `cve-service-itest-${run}`,
      );
    };
    await expect.poll(findTarget, { timeout: 20_000, interval: 1_000 }).toBeDefined();
    const target = await findTarget();
    const closed = await fetch(`${base}/connections/${encodeURIComponent(target?.name ?? '')}`, {
      method: 'DELETE',
      headers: { authorization: auth, 'x-reason': 'integration test' },
    });
    expect(closed.status).toBe(204);

    await waitFor(() => (connection.isConnected ? undefined : true), 5_000).catch(() => true);
    await waitFor(() => (connection.isConnected && publisher.isReady ? true : undefined), 20_000);
    await expect
      .poll(
        async () => {
          await publish('recovered', { cveId: 'CVE-2026-0006' }).catch(() => undefined);
          return received.length > 0;
        },
        { timeout: 20_000, interval: 1_000 },
      )
      .toBe(true);
  });
});

describe('RabbitMQ permissions', () => {
  it('prevents a service from touching another service’s resources', async () => {
    const poc = await connect(serviceRabbitMqUrl('poc-service'));
    try {
      const own = consumerTopology('cve-service', `itest-${run}-foreign`, 0);
      let channel = await poc.createChannel();
      channel.on('error', () => undefined);
      await expect(channel.assertQueue(own.queue)).rejects.toThrow(/ACCESS_REFUSED/);

      channel = await poc.createChannel();
      channel.on('error', () => undefined);
      await expect(
        channel.assertExchange('cve.events', 'topic', { durable: true, arguments: { x: 1 } }),
      ).rejects.toThrow(/ACCESS_REFUSED|PRECONDITION_FAILED/);

      // Publishing into another service's internal exchange is refused by the broker.
      const confirm = await poc.createConfirmChannel();
      const closed = new Promise<Error>((resolve) => confirm.once('error', resolve));
      confirm.publish('cve-service.internal', 'x', Buffer.from('{}'));
      await expect(closed).resolves.toMatchObject({
        message: expect.stringMatching(/ACCESS_REFUSED|NOT_FOUND/) as unknown,
      });
    } finally {
      await poc.close();
    }
  });

  it('does not allow service users into the management API', async () => {
    const password = requireEnv('POC_SERVICE_RABBITMQ_PASSWORD');
    const res = await fetch(`http://${integrationHost()}:15672/api/overview`, {
      headers: {
        authorization: `Basic ${Buffer.from(`poc-service:${password}`).toString('base64')}`,
      },
    });
    expect(res.status).toBe(401);
  });
});
