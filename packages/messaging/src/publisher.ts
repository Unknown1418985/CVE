import {
  domainEventEnvelopeSchema,
  type DomainEventEnvelope,
  type ServiceName,
} from '@cve/contracts';
import type { Logger } from '@cve/logger';
import type { ChannelModel, ConfirmChannel, Message } from 'amqplib';

import type { RabbitMqConnection } from './connection.js';
import { EventPublishError, errorMessage } from './errors.js';
import { EVENTS_EXCHANGE } from './topology.js';

export const CORRELATION_ID_HEADER = 'x-correlation-id';
export const EVENT_VERSION_HEADER = 'x-event-version';

export interface EventPublisherOptions {
  readonly connection: RabbitMqConnection;
  /** The publishing service; events claiming another producer are rejected. */
  readonly producer: ServiceName;
  readonly logger: Logger;
  /** Maximum time to wait for a broker confirm. Default 10 seconds. */
  readonly confirmTimeoutMs?: number;
}

/** Serialises an envelope into the AMQP body and properties used across the platform. */
export function toAmqpMessage(event: DomainEventEnvelope): {
  readonly routingKey: string;
  readonly content: Buffer;
  readonly properties: {
    persistent: true;
    mandatory: true;
    contentType: 'application/json';
    contentEncoding: 'utf-8';
    messageId: string;
    type: string;
    appId: string;
    timestamp: number;
    headers: Record<string, string | number>;
  };
} {
  return {
    routingKey: event.eventType,
    content: Buffer.from(JSON.stringify(event), 'utf8'),
    properties: {
      persistent: true,
      mandatory: true,
      contentType: 'application/json',
      contentEncoding: 'utf-8',
      messageId: event.eventId,
      type: event.eventType,
      appId: event.producer,
      timestamp: Math.floor(Date.parse(event.occurredAt) / 1000),
      headers: {
        [EVENT_VERSION_HEADER]: event.eventVersion,
        ...(event.correlationId === undefined
          ? {}
          : { [CORRELATION_ID_HEADER]: event.correlationId }),
      },
    },
  };
}

/**
 * Publishes domain events to the `cve.events` topic exchange on a confirm channel.
 * `publish` resolves only after the broker has confirmed the message, so callers (such as
 * the outbox relay) can safely mark an event as delivered.
 */
export class EventPublisher {
  private channel: ConfirmChannel | undefined;
  private readonly setup = (model: ChannelModel) => this.openChannel(model);

  constructor(private readonly options: EventPublisherOptions) {}

  get isReady(): boolean {
    return this.channel !== undefined;
  }

  async start(): Promise<void> {
    await this.options.connection.addSetup(this.setup);
  }

  private async openChannel(model: ChannelModel): Promise<void> {
    const { logger, connection } = this.options;
    const channel = await model.createConfirmChannel();
    try {
      // The exchange is provisioned centrally; a passive check fails loudly when it is missing.
      await channel.checkExchange(EVENTS_EXCHANGE);
    } catch (error) {
      throw new EventPublishError(
        `Exchange "${EVENTS_EXCHANGE}" is not available: ${errorMessage(error)}`,
        { cause: error },
      );
    }
    channel.on('return', (message: Message) => {
      logger.warn(
        { routingKey: message.fields.routingKey, eventId: message.properties.messageId as unknown },
        'event was not routed to any queue',
      );
    });
    channel.on('error', (error: Error) => {
      logger.error({ err: error }, 'publisher channel error');
    });
    channel.on('close', () => {
      if (this.channel !== channel) return;
      this.channel = undefined;
      if (!connection.isClosing && connection.isConnected) {
        logger.warn('publisher channel closed, reopening');
        void connection.rerunSetup(this.setup);
      }
    });
    this.channel = channel;
  }

  async publish(event: DomainEventEnvelope): Promise<void> {
    const parsed = domainEventEnvelopeSchema.safeParse(event);
    if (!parsed.success) {
      throw new EventPublishError(`Invalid event envelope: ${parsed.error.message}`);
    }
    if (event.producer !== this.options.producer) {
      throw new EventPublishError(
        `Event producer "${event.producer}" does not match publisher "${this.options.producer}"`,
      );
    }
    const channel = this.channel;
    if (!channel) {
      throw new EventPublishError('RabbitMQ publisher channel is not available');
    }

    const message = toAmqpMessage(event);
    const timeoutMs = this.options.confirmTimeoutMs ?? 10_000;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new EventPublishError(`Broker confirm timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      try {
        channel.publish(
          EVENTS_EXCHANGE,
          message.routingKey,
          message.content,
          message.properties,
          (error: unknown) => {
            clearTimeout(timer);
            if (error) {
              reject(
                new EventPublishError(`Broker rejected event: ${errorMessage(error)}`, {
                  cause: error,
                }),
              );
            } else {
              resolve();
            }
          },
        );
      } catch (error) {
        clearTimeout(timer);
        reject(
          new EventPublishError(`Failed to publish event: ${errorMessage(error)}`, {
            cause: error,
          }),
        );
      }
    });
    this.options.logger.debug(
      { eventId: event.eventId, eventType: event.eventType, correlationId: event.correlationId },
      'event published',
    );
  }

  async close(): Promise<void> {
    this.options.connection.removeSetup(this.setup);
    const channel = this.channel;
    this.channel = undefined;
    if (channel) {
      await channel.close().catch((error: unknown) => {
        this.options.logger.warn({ err: error }, 'failed to close publisher channel');
      });
    }
  }
}
