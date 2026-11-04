import { isServiceName, type ServiceName } from '@cve/contracts';

/**
 * RabbitMQ topology conventions shared by publishers, consumers and the infrastructure
 * provisioner. Keeping them in one place means permissions granted to a service user always
 * match the resources that service declares.
 */

/** Virtual host used by the platform. */
export const PLATFORM_VHOST = 'cve';

/**
 * Durable topic exchange carrying every domain event. The routing key is the event type
 * (`<domain>.<entity>.<action>`), so consumers bind with patterns such as `cve.record.*`.
 * Declared by the infrastructure provisioner; services only check that it exists.
 */
export const EVENTS_EXCHANGE = 'cve.events';

/** Consumer names are kebab-case and become part of queue names. */
const CONSUMER_NAME_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;

/** Binding keys follow the event type format with optional `*` / `#` wildcards per segment. */
const BINDING_KEY_PATTERN = /^(?:[a-z]+(?:-[a-z]+)*|\*|#)(?:\.(?:[a-z]+(?:-[a-z]+)*|\*|#))*$/;

export interface ConsumerTopology {
  /** Direct exchange owned by the service for retries and dead-lettering. */
  readonly internalExchange: string;
  /** Main queue the consumer reads from. */
  readonly queue: string;
  /** Final destination of messages that cannot be processed. */
  readonly deadLetterQueue: string;
  /** Delay queues, one per retry attempt; index 0 holds the delay before attempt 2. */
  readonly retryQueues: readonly string[];
}

export function assertConsumerName(consumer: string): void {
  if (!CONSUMER_NAME_PATTERN.test(consumer) || consumer.length > 64) {
    throw new Error(`Invalid consumer name "${consumer}": use kebab-case, at most 64 characters`);
  }
}

export function assertBindingKey(key: string): void {
  if (!BINDING_KEY_PATTERN.test(key)) {
    throw new Error(`Invalid binding key "${key}"`);
  }
}

function assertService(service: string): asserts service is ServiceName {
  if (!isServiceName(service)) {
    throw new Error(`Unknown service "${service}"`);
  }
}

/** Name of the per-service direct exchange used for retries and dead-lettering. */
export function serviceInternalExchange(service: ServiceName): string {
  assertService(service);
  return `${service}.internal`;
}

/**
 * Derives every resource name for one consumer. `retryDelaysMs.length` retry queues are
 * created; a message is therefore attempted at most `retryDelaysMs.length + 1` times.
 */
export function consumerTopology(
  service: ServiceName,
  consumer: string,
  retryCount: number,
): ConsumerTopology {
  assertService(service);
  assertConsumerName(consumer);
  if (!Number.isInteger(retryCount) || retryCount < 0 || retryCount > 10) {
    throw new Error('retryCount must be an integer between 0 and 10');
  }
  const queue = `${service}.${consumer}`;
  return {
    internalExchange: serviceInternalExchange(service),
    queue,
    deadLetterQueue: `${queue}.dlq`,
    retryQueues: Array.from({ length: retryCount }, (_, index) => `${queue}.retry.${index + 1}`),
  };
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export interface ServicePermissions {
  readonly configure: string;
  readonly write: string;
  readonly read: string;
}

/**
 * Least-privilege RabbitMQ permissions for a service user:
 * - configure (declare/delete) only resources prefixed with the service name;
 * - write (publish, bind destinations) to the events exchange and its own resources;
 * - read (consume, bind sources) from the events exchange and its own resources.
 * A service can therefore never declare, consume from or publish into another
 * service's queues.
 */
export function servicePermissions(service: ServiceName): ServicePermissions {
  assertService(service);
  const own = `${escapeRegex(service)}\\..*`;
  const events = escapeRegex(EVENTS_EXCHANGE);
  return {
    configure: `^${own}$`,
    write: `^(${events}|${own})$`,
    read: `^(${events}|${own})$`,
  };
}
