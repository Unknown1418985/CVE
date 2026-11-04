import type { DependencyCheck } from '@cve/contracts';

import type { RabbitMqConnection } from './connection.js';

/** Structurally compatible with `HealthIndicator` from `@cve/shared`. */
export interface MessagingHealthIndicator {
  readonly name: string;
  readonly critical: boolean;
  check(timeoutMs: number): Promise<DependencyCheck>;
}

/** Reports whether the AMQP connection is currently established. */
export function createRabbitMqHealthIndicator(
  connection: RabbitMqConnection,
  options: { name?: string; critical?: boolean } = {},
): MessagingHealthIndicator {
  const name = options.name ?? 'rabbitmq';
  return {
    name,
    critical: options.critical ?? true,
    check: () =>
      Promise.resolve(
        connection.isConnected
          ? { name, status: 'ok', message: 'amqp connection open' }
          : { name, status: 'down', message: 'amqp connection not established' },
      ),
  };
}
