import { BACKEND_SERVICE_NAMES, type BackendServiceName } from '@cve/contracts';
import type { Logger } from '@cve/logger';
import {
  EVENTS_EXCHANGE,
  PLATFORM_VHOST,
  servicePermissions,
  type ServicePermissions,
} from '@cve/messaging';

import type { HttpClient } from './http-client.js';

export interface RabbitMqServiceUser {
  readonly service: BackendServiceName;
  readonly password: string;
  readonly permissions: ServicePermissions;
  /** Connection and channel caps; a leaking service cannot exhaust the broker. */
  readonly maxConnections: number;
  readonly maxChannels: number;
}

export interface RabbitMqPlan {
  readonly vhost: string;
  readonly adminUser: string;
  readonly eventsExchange: string;
  readonly users: readonly RabbitMqServiceUser[];
}

export function buildRabbitMqPlan(
  adminUser: string,
  passwordFor: (service: BackendServiceName) => string,
): RabbitMqPlan {
  return {
    vhost: PLATFORM_VHOST,
    adminUser,
    eventsExchange: EVENTS_EXCHANGE,
    users: BACKEND_SERVICE_NAMES.map((service) => ({
      service,
      password: passwordFor(service),
      permissions: servicePermissions(service),
      maxConnections: 10,
      maxChannels: 200,
    })),
  };
}

const enc = encodeURIComponent;

export async function applyRabbitMqPlan(
  client: HttpClient,
  plan: RabbitMqPlan,
  logger: Logger,
): Promise<void> {
  const vhost = enc(plan.vhost);

  await client.expect('PUT', `/api/vhosts/${vhost}`, {
    description: 'CVE Intelligence Platform',
    default_queue_type: 'quorum',
    tracing: false,
  });
  await client.expect('PUT', `/api/permissions/${vhost}/${enc(plan.adminUser)}`, {
    configure: '.*',
    write: '.*',
    read: '.*',
  });
  await client.expect('PUT', `/api/exchanges/${vhost}/${enc(plan.eventsExchange)}`, {
    type: 'topic',
    durable: true,
    auto_delete: false,
    internal: false,
    arguments: {},
  });
  logger.info(
    { vhost: plan.vhost, exchange: plan.eventsExchange },
    'rabbitmq vhost and events exchange ready',
  );

  for (const user of plan.users) {
    const name = enc(user.service);
    // PUT replaces the password, so rotating a secret in .env takes effect on the next run.
    await client.expect('PUT', `/api/users/${name}`, { password: user.password, tags: '' });
    await client.expect('PUT', `/api/permissions/${vhost}/${name}`, user.permissions);
    await client.expect('PUT', `/api/user-limits/${name}/max-connections`, {
      value: user.maxConnections,
    });
    await client.expect('PUT', `/api/user-limits/${name}/max-channels`, {
      value: user.maxChannels,
    });
    logger.info(
      { user: user.service, permissions: user.permissions },
      'rabbitmq service user provisioned',
    );
  }

  // The image does not create `guest` when a default user is configured; remove it if present.
  const guest = await client.expect('DELETE', '/api/users/guest', undefined, [404]);
  if (guest.status !== 404) logger.warn('removed rabbitmq guest user');
}
