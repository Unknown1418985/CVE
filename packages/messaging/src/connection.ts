import type { Logger } from '@cve/logger';
import { connect, type ChannelModel, type RecoveringChannelModel } from 'amqplib';

import { errorMessage } from './errors.js';

/** Runs after every (re)connection; typically opens a channel and declares resources. */
export type ConnectionSetup = (model: ChannelModel) => Promise<void>;

export interface RabbitMqConnectionOptions {
  /** `amqp://user:password@host:5672/vhost` */
  readonly url: string;
  /** Shown in the RabbitMQ management UI, e.g. the service name. */
  readonly connectionName: string;
  readonly logger: Logger;
  /** Retries before the first successful connection. Default 10 (fail fast at startup). */
  readonly initialMaxRetries?: number;
  readonly initialDelayMs?: number;
  readonly maxDelayMs?: number;
  /** AMQP heartbeat in seconds. Default 30. */
  readonly heartbeatSeconds?: number;
}

/** Removes credentials from an AMQP URL before it is logged. */
export function redactAmqpUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.password !== '') parsed.password = '****';
    return parsed.toString();
  } catch {
    return '[invalid url]';
  }
}

/** Adds the AMQP heartbeat to the URL unless it already sets one. */
export function withHeartbeat(url: string, seconds: number): string {
  const parsed = new URL(url);
  if (!parsed.searchParams.has('heartbeat')) parsed.searchParams.set('heartbeat', String(seconds));
  return parsed.toString();
}

/**
 * Long-lived RabbitMQ connection with automatic recovery (exponential backoff with jitter).
 * Components register setups; every setup runs again after a reconnect so channels,
 * consumers and declarations are restored.
 */
export class RabbitMqConnection {
  private recovering: RecoveringChannelModel | undefined;
  private current: ChannelModel | undefined;
  private readonly setups = new Set<ConnectionSetup>();
  private closing = false;

  constructor(private readonly options: RabbitMqConnectionOptions) {}

  get isConnected(): boolean {
    return this.current !== undefined;
  }

  /** The live channel model, if connected. */
  get model(): ChannelModel | undefined {
    return this.current;
  }

  get isClosing(): boolean {
    return this.closing;
  }

  async connect(): Promise<void> {
    if (this.recovering) return;
    const { logger } = this.options;
    const recovering = await connect(
      withHeartbeat(this.options.url, this.options.heartbeatSeconds ?? 30),
      {
        clientProperties: { connection_name: this.options.connectionName },
        timeout: 10_000,
        recovery: {
          initialDelay: this.options.initialDelayMs ?? 500,
          maxDelay: this.options.maxDelayMs ?? 30_000,
          initialMaxRetries: this.options.initialMaxRetries ?? 10,
          maxRetries: Number.POSITIVE_INFINITY,
          waitForConnect: false,
          setup: async (model: ChannelModel) => {
            for (const setup of this.setups) {
              await setup(model);
            }
          },
        },
      },
    );
    this.recovering = recovering;

    recovering.on('connect', (model: ChannelModel) => {
      this.current = model;
      logger.info({ broker: redactAmqpUrl(this.options.url) }, 'rabbitmq connected');
    });
    recovering.on('disconnect', (error: Error) => {
      this.current = undefined;
      if (!this.closing) logger.warn({ err: error }, 'rabbitmq connection lost');
    });
    recovering.on('connect-failed', (error: Error) => {
      logger.error({ err: error }, 'rabbitmq connection attempt failed');
    });
    recovering.on('reconnect-scheduled', (info: { attempt: number; delay: number }) => {
      logger.warn({ attempt: info.attempt, delayMs: info.delay }, 'rabbitmq reconnect scheduled');
    });
    recovering.on('reconnect-failed', (error: Error) => {
      logger.fatal({ err: error }, 'rabbitmq recovery abandoned');
    });
    recovering.on('blocked', (reason: string) => {
      logger.warn({ reason }, 'rabbitmq connection blocked by broker');
    });
    recovering.on('unblocked', () => {
      logger.info('rabbitmq connection unblocked');
    });
    recovering.on('error', (error: Error) => {
      logger.error({ err: error }, 'rabbitmq connection error');
    });

    await recovering.waitForConnect();
  }

  /**
   * Registers a setup that runs now (when connected) and after every reconnect.
   * Errors from the immediate run are propagated to the caller.
   */
  async addSetup(setup: ConnectionSetup): Promise<void> {
    this.setups.add(setup);
    if (this.current) {
      await setup(this.current);
    }
  }

  removeSetup(setup: ConnectionSetup): void {
    this.setups.delete(setup);
  }

  /**
   * Re-runs one setup on the live connection, used when a single channel is closed by the
   * broker (for example after a precondition failure) while the connection stays up.
   */
  async rerunSetup(setup: ConnectionSetup, attempt = 1): Promise<void> {
    if (this.closing || !this.setups.has(setup)) return;
    const model = this.current;
    if (!model) return; // The next reconnect runs every setup.
    try {
      await setup(model);
    } catch (error) {
      const delayMs = Math.min(30_000, 500 * 2 ** (attempt - 1));
      this.options.logger.error(
        { err: error, attempt, delayMs },
        `rabbitmq channel setup failed: ${errorMessage(error)}`,
      );
      setTimeout(() => {
        void this.rerunSetup(setup, attempt + 1);
      }, delayMs).unref();
    }
  }

  async close(): Promise<void> {
    this.closing = true;
    this.setups.clear();
    const recovering = this.recovering;
    this.recovering = undefined;
    this.current = undefined;
    if (recovering) {
      await recovering.close();
    }
  }
}
