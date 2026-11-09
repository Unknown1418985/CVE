import { domainEventSchema, type ServiceName } from '@cve/contracts';
import type { Logger } from '@cve/logger';
import type { ChannelModel, ConfirmChannel, ConsumeMessage } from 'amqplib';
import type { z } from 'zod';

import type { RabbitMqConnection } from './connection.js';
import { boundedLabel } from '@cve/metrics';

import type { DomainEvent } from './domain-event.js';
import { NonRetryableEventError, errorMessage } from './errors.js';
import { eventHandlerDuration, recordConsumed, type ConsumeOutcome } from './metrics.js';
import type { ProcessedEventStore } from './processed-events.js';
import { CORRELATION_ID_HEADER } from './publisher.js';
import {
  EVENTS_EXCHANGE,
  assertBindingKey,
  consumerTopology,
  type ConsumerTopology,
} from './topology.js';

export const ATTEMPT_HEADER = 'x-attempt';
export const LAST_ERROR_HEADER = 'x-last-error';

/** Default retry schedule: 3 retries after 5 s, 30 s and 2 min, then the dead-letter queue. */
export const DEFAULT_RETRY_DELAYS_MS: readonly number[] = [5_000, 30_000, 120_000];

export interface EventHandlerContext {
  /** 1 for the first delivery, incremented on every retry. */
  readonly attempt: number;
  readonly redelivered: boolean;
  readonly logger: Logger;
}

export interface EventSubscription<TPayload> {
  /** Kebab-case consumer name, unique within the service, e.g. `kev-status-updater`. */
  readonly consumer: string;
  /** Routing-key patterns on the events exchange, e.g. `cve.record.created` or `cve.record.*`. */
  readonly eventTypes: readonly string[];
  /** Schema the event payload must satisfy; invalid events go straight to the DLQ. */
  readonly payloadSchema: z.ZodType<TPayload>;
  readonly handle: (event: DomainEvent<TPayload>, context: EventHandlerContext) => Promise<void>;
  /** Delay before each retry. Changing it requires a new consumer name (queue arguments are fixed). */
  readonly retryDelaysMs?: readonly number[];
  /** Unacknowledged messages in flight. Default 10. */
  readonly prefetch?: number;
}

export interface EventConsumerOptions {
  readonly connection: RabbitMqConnection;
  readonly service: ServiceName;
  readonly logger: Logger;
  /** Enables duplicate suppression by event ID. Strongly recommended for side-effecting handlers. */
  readonly processedEvents?: ProcessedEventStore;
}

export type FailureAction =
  | { readonly kind: 'retry'; readonly retryQueue: string; readonly nextAttempt: number }
  | { readonly kind: 'dead-letter'; readonly reason: string };

/** Decides what happens to a message whose handler failed. */
export function decideFailureAction(
  topology: ConsumerTopology,
  attempt: number,
  error: unknown,
): FailureAction {
  if (error instanceof NonRetryableEventError) {
    return { kind: 'dead-letter', reason: `non-retryable: ${error.message}` };
  }
  const retryQueue = topology.retryQueues[attempt - 1];
  if (retryQueue === undefined) {
    return { kind: 'dead-letter', reason: `retries exhausted after ${attempt} attempt(s)` };
  }
  return { kind: 'retry', retryQueue, nextAttempt: attempt + 1 };
}

export function readAttempt(message: ConsumeMessage): number {
  const raw: unknown = message.properties.headers?.[ATTEMPT_HEADER];
  const value = typeof raw === 'number' ? raw : typeof raw === 'string' ? Number(raw) : 1;
  return Number.isInteger(value) && value >= 1 ? value : 1;
}

function validateRetryDelays(delays: readonly number[]): void {
  for (const delay of delays) {
    if (!Number.isInteger(delay) || delay < 100 || delay > 24 * 60 * 60 * 1000) {
      throw new Error('retryDelaysMs entries must be integers between 100 ms and 24 h');
    }
  }
}

/**
 * Declares the consumer's queues and processes domain events with validation, idempotency,
 * delayed retries and dead-lettering:
 *
 *   cve.events ──binding──▶ <service>.<consumer> ──handler fails──▶ <service>.internal
 *        ▲                        │      ▲                              │ key = retry queue
 *        │                        │      └──── TTL expires ◀── <queue>.retry.<n>
 *        │                        └─ invalid / exhausted ─▶ <queue>.dlq
 */
export class EventConsumer {
  private readonly subscriptions: {
    readonly setup: (model: ChannelModel) => Promise<void>;
    channel: ConfirmChannel | undefined;
    consumerTag: string | undefined;
  }[] = [];
  private readonly inFlight = new Set<Promise<void>>();

  constructor(private readonly options: EventConsumerOptions) {}

  async subscribe<TPayload>(subscription: EventSubscription<TPayload>): Promise<ConsumerTopology> {
    const delays = subscription.retryDelaysMs ?? DEFAULT_RETRY_DELAYS_MS;
    validateRetryDelays(delays);
    if (subscription.eventTypes.length === 0) {
      throw new Error('A subscription needs at least one event type');
    }
    subscription.eventTypes.forEach(assertBindingKey);
    const topology = consumerTopology(this.options.service, subscription.consumer, delays.length);
    const schema = domainEventSchema(subscription.payloadSchema);
    const logger = this.options.logger.child({ consumer: subscription.consumer });
    const { connection } = this.options;

    const entry: (typeof this.subscriptions)[number] = {
      channel: undefined,
      consumerTag: undefined,
      setup: async (model) => {
        const channel = await model.createConfirmChannel();
        channel.on('error', (error: Error) => {
          logger.error({ err: error }, 'consumer channel error');
        });
        channel.on('close', () => {
          if (entry.channel !== channel) return;
          entry.channel = undefined;
          if (!connection.isClosing && connection.isConnected) {
            logger.warn('consumer channel closed, reopening');
            void connection.rerunSetup(entry.setup);
          }
        });
        await declareConsumerTopology(channel, topology, subscription.eventTypes, delays);
        await channel.prefetch(subscription.prefetch ?? 10);
        entry.channel = channel;
        const { consumerTag } = await channel.consume(
          topology.queue,
          (message) => {
            if (message === null) {
              logger.error('consumer cancelled by broker');
              return;
            }
            const task = this.handleMessage(
              channel,
              message,
              topology,
              schema,
              subscription,
              logger,
            )
              .catch((error: unknown) => {
                // Only reachable when the channel itself failed (ack/nack on a closed channel);
                // the broker redelivers unacknowledged messages after reconnecting.
                logger.error({ err: error }, 'event processing aborted');
              })
              .finally(() => this.inFlight.delete(task));
            this.inFlight.add(task);
          },
          { noAck: false },
        );
        entry.consumerTag = consumerTag;
        logger.info(
          { queue: topology.queue, bindings: subscription.eventTypes },
          'consumer started',
        );
      },
    };
    this.subscriptions.push(entry);
    await connection.addSetup(entry.setup);
    return topology;
  }

  private async handleMessage<TPayload>(
    channel: ConfirmChannel,
    message: ConsumeMessage,
    topology: ConsumerTopology,
    schema: z.ZodType<DomainEvent<TPayload>>,
    subscription: EventSubscription<TPayload>,
    baseLogger: Logger,
  ): Promise<void> {
    const attempt = readAttempt(message);
    const correlationId: unknown = message.properties.headers?.[CORRELATION_ID_HEADER];
    const logger = baseLogger.child({
      eventId: message.properties.messageId as unknown,
      attempt,
      ...(typeof correlationId === 'string' ? { correlationId } : {}),
    });

    let event: DomainEvent<TPayload>;
    try {
      const raw: unknown = JSON.parse(message.content.toString('utf8'));
      event = schema.parse(raw);
    } catch (error) {
      logger.error({ err: error }, 'invalid event moved to dead-letter queue');
      channel.nack(message, false, false);
      recordConsumed(topology.queue, undefined, 'invalid');
      return;
    }

    try {
      const store = this.options.processedEvents;
      if (store && (await store.isProcessed(subscription.consumer, event.eventId))) {
        logger.info({ eventType: event.eventType }, 'duplicate event skipped');
        channel.ack(message);
        recordConsumed(topology.queue, event.eventType, 'duplicate');
        return;
      }
      const timer = eventHandlerDuration().startTimer({
        queue: boundedLabel(topology.queue),
        event_type: boundedLabel(event.eventType),
      });
      try {
        await subscription.handle(event, {
          attempt,
          redelivered: message.fields.redelivered,
          logger,
        });
      } finally {
        timer();
      }
      if (store) await store.markProcessed(subscription.consumer, event.eventId);
      channel.ack(message);
      recordConsumed(topology.queue, event.eventType, 'processed');
    } catch (error) {
      const outcome = await this.handleFailure(channel, message, topology, attempt, error, logger);
      recordConsumed(topology.queue, event.eventType, outcome);
    }
  }

  private async handleFailure(
    channel: ConfirmChannel,
    message: ConsumeMessage,
    topology: ConsumerTopology,
    attempt: number,
    error: unknown,
    logger: Logger,
  ): Promise<ConsumeOutcome> {
    const action = decideFailureAction(topology, attempt, error);
    if (action.kind === 'dead-letter') {
      logger.error({ err: error, reason: action.reason }, 'event moved to dead-letter queue');
      channel.nack(message, false, false);
      return 'dead_lettered';
    }
    try {
      await new Promise<void>((resolve, reject) => {
        channel.publish(
          topology.internalExchange,
          action.retryQueue,
          message.content,
          {
            ...message.properties,
            persistent: true,
            headers: {
              ...message.properties.headers,
              [ATTEMPT_HEADER]: action.nextAttempt,
              [LAST_ERROR_HEADER]: errorMessage(error).slice(0, 500),
            },
          },
          (publishError: unknown) => {
            if (publishError)
              reject(
                publishError instanceof Error
                  ? publishError
                  : new Error(errorMessage(publishError)),
              );
            else resolve();
          },
        );
      });
      logger.warn(
        { err: error, nextAttempt: action.nextAttempt },
        'event handler failed, retry scheduled',
      );
      channel.ack(message);
      return 'retry_scheduled';
    } catch (publishError) {
      // The retry could not be stored; return the message to the queue so it is not lost.
      logger.error({ err: publishError }, 'failed to schedule retry, requeueing event');
      channel.nack(message, false, true);
      return 'requeued';
    }
  }

  /** Stops consuming, waits for in-flight handlers to finish, then closes the channels. */
  async close(): Promise<void> {
    for (const entry of this.subscriptions) {
      this.options.connection.removeSetup(entry.setup);
      if (entry.channel && entry.consumerTag !== undefined) {
        await entry.channel.cancel(entry.consumerTag).catch((error: unknown) => {
          this.options.logger.warn({ err: error }, 'failed to cancel consumer');
        });
      }
    }
    await Promise.allSettled([...this.inFlight]);
    for (const entry of this.subscriptions) {
      const channel = entry.channel;
      entry.channel = undefined;
      if (channel) {
        await channel.close().catch((error: unknown) => {
          this.options.logger.warn({ err: error }, 'failed to close consumer channel');
        });
      }
    }
    this.subscriptions.length = 0;
  }
}

/** Idempotently declares the queues, exchange and bindings for one consumer. */
export async function declareConsumerTopology(
  channel: ConfirmChannel,
  topology: ConsumerTopology,
  eventTypes: readonly string[],
  retryDelaysMs: readonly number[],
): Promise<void> {
  const quorum = { 'x-queue-type': 'quorum' };
  await channel.assertExchange(topology.internalExchange, 'direct', { durable: true });

  await channel.assertQueue(topology.deadLetterQueue, { durable: true, arguments: quorum });
  await channel.bindQueue(
    topology.deadLetterQueue,
    topology.internalExchange,
    topology.deadLetterQueue,
  );

  await channel.assertQueue(topology.queue, {
    durable: true,
    arguments: {
      ...quorum,
      'x-dead-letter-exchange': topology.internalExchange,
      'x-dead-letter-routing-key': topology.deadLetterQueue,
    },
  });
  // Messages returning from a retry queue are routed back by queue name.
  await channel.bindQueue(topology.queue, topology.internalExchange, topology.queue);
  for (const eventType of eventTypes) {
    await channel.bindQueue(topology.queue, EVENTS_EXCHANGE, eventType);
  }

  for (const [index, retryQueue] of topology.retryQueues.entries()) {
    await channel.assertQueue(retryQueue, {
      durable: true,
      arguments: {
        ...quorum,
        'x-message-ttl': retryDelaysMs[index],
        'x-dead-letter-exchange': topology.internalExchange,
        'x-dead-letter-routing-key': topology.queue,
      },
    });
    await channel.bindQueue(retryQueue, topology.internalExchange, retryQueue);
  }
}
