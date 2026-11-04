import { isServiceName, type ServiceName } from '@cve/contracts';

/**
 * Every Redis key a service writes starts with `cve:<service>:`. The Redis ACL generated in
 * `infra/redis` grants each service user access to exactly this pattern, so services cannot
 * read or modify each other's queues or cache entries.
 */
export function redisKeyPrefix(service: ServiceName): string {
  if (!isServiceName(service)) throw new Error(`Unknown service "${String(service)}"`);
  return `cve:${service}:`;
}

/** BullMQ key prefix (BullMQ appends `:<queue>:<suffix>`). */
export function bullPrefix(service: ServiceName): string {
  return `${redisKeyPrefix(service)}bull`;
}

const QUEUE_NAME_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;

export function assertQueueName(name: string): void {
  if (!QUEUE_NAME_PATTERN.test(name) || name.length > 64) {
    throw new Error(`Invalid queue name "${name}": use kebab-case, at most 64 characters`);
  }
}
