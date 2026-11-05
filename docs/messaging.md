# Messaging and background jobs

Two shared packages implement asynchronous communication (CLAUDE.md §4):

- **`@cve/messaging`** — domain events between services over RabbitMQ.
- **`@cve/jobs`** — retryable and scheduled work inside a service over BullMQ/Redis.

Use events to tell other services that something happened; use jobs for work a service does for
itself (synchronisation runs, downloads, report generation).

## RabbitMQ topology

```
producer ──publish (confirm)──▶ cve.events (topic, durable; routing key = eventType)
                                     │ binding: e.g. cve.record.*
                                     ▼
              ┌──────────── <service>.<consumer>  (quorum queue) ──── handler
              │                      ▲                                   │ fails, retries left
              │ TTL expires          │ routed back by queue name         ▼
   <queue>.retry.<n>  ◀──────────── <service>.internal (direct) ◀─── republish with x-attempt+1
                                     │
   invalid / non-retryable / exhausted → nack ─▶ dead-letter ─▶ <queue>.dlq
```

- `cve.events` and the `cve` vhost are created by the infra-provisioner. Services only check that
  the exchange exists, so a missing provisioning step fails loudly.
- Each consumer owns a main queue, one delay queue per retry (fixed TTL each, so there is no
  head-of-line blocking) and a dead-letter queue, all prefixed with the service name. RabbitMQ
  permissions (`servicePermissions`) let a service declare and read only these, and publish only
  to `cve.events` and its own exchange.
- Messages are persistent, published on confirm channels (`publish` resolves after the broker
  confirm), carry `messageId = eventId`, `type = eventType`, `appId = producer`, and the
  `x-correlation-id` header.
- Consumers validate the envelope and payload with Zod. Invalid messages go straight to the DLQ;
  handler errors are retried with the configured delays (default 5 s, 30 s, 2 min) and then
  dead-lettered. `NonRetryableEventError` skips the retries.
- Delivery is at least once. Pass a `ProcessedEventStore` (`RedisProcessedEventStore`) to skip
  events that were already handled.
- The connection recovers automatically (exponential backoff with jitter) and re-declares channels
  and consumers; startup fails after 10 attempts.
- Changing a consumer's retry delays changes queue arguments, which RabbitMQ refuses for an
  existing queue: use a new consumer name, or delete the old queues.

### Publishing

```ts
import { EventPublisher, RabbitMqConnection, createDomainEvent } from '@cve/messaging';

const connection = new RabbitMqConnection({
  url: env.RABBITMQ_URL,
  connectionName: SERVICE_NAME,
  logger,
});
await connection.connect();
const publisher = new EventPublisher({ connection, producer: SERVICE_NAME, logger });
await publisher.start();

await publisher.publish(
  createDomainEvent({
    eventType: 'cve.record.created',
    producer: SERVICE_NAME,
    payload: { cveId: 'CVE-2026-0001' },
    correlationId,
  }),
);
```

For events that must not be lost when the database commit succeeds but publishing fails, write
them to the service's outbox table in the same transaction and let `OutboxRelay` publish them.
`OutboxRelay` takes an `OutboxStore` implemented by the service on its own Prisma schema
(`claimDue` should use `SELECT … FOR UPDATE SKIP LOCKED`); the Identity and CVE Services implement it.

### Consuming

```ts
import { EventConsumer, RedisProcessedEventStore } from '@cve/messaging';
import { redisKeyPrefix } from '@cve/jobs';

const consumer = new EventConsumer({
  connection,
  service: SERVICE_NAME,
  logger,
  processedEvents: new RedisProcessedEventStore({ redis, keyPrefix: redisKeyPrefix(SERVICE_NAME) }),
});

await consumer.subscribe({
  consumer: 'kev-status-updater',
  eventTypes: ['intelligence.kev-entry.added'],
  payloadSchema: z.object({ cveId: z.string() }),
  handle: async (event, { attempt, logger }) => {
    /* … */
  },
});
```

Call `consumer.close()` on shutdown: it cancels consumption, waits for in-flight handlers, then
closes the channels. `createRabbitMqHealthIndicator(connection)` plugs into the health module.

## BullMQ jobs

- Keys are prefixed `cve:<service>:bull`, matching the service's Redis ACL (`cve:<service>:*`).
- `defineJob` declares the queue, job name, payload schema, retry policy (default 5 attempts,
  exponential backoff from 2 s), retention (completed: 1 day / 1 000 jobs; failed: 14 days /
  10 000 jobs) and an optional timeout.
- `JobQueue.add` validates the payload and accepts an idempotency key (`jobId`); adding the same
  ID twice is a no-op. `schedule` upserts a recurring job (`everyMs` or `cron` + `timezone`).
- `JobWorker` re-validates payloads read from Redis, fails invalid ones permanently
  (`PermanentJobError` does the same from a handler), enforces the timeout through an
  `AbortSignal`, supports concurrency and rate limits (for upstream API quotas), and logs every
  failure. `close()` aborts running handlers and waits for them.

```ts
import { JobQueue, JobWorker, createRedisConnection, defineJob } from '@cve/jobs';

const nvdSync = defineJob({
  queue: 'nvd-sync',
  name: 'sync-window',
  payloadSchema: z.object({ from: z.iso.datetime(), to: z.iso.datetime() }),
  timeoutMs: 10 * 60_000,
});

const redis = createRedisConnection({
  url: env.REDIS_URL,
  connectionName: `${SERVICE_NAME}:jobs`,
  logger,
  role: 'worker',
});
const queue = new JobQueue(nvdSync, { connection: redis, service: SERVICE_NAME, logger });
await queue.schedule('nvd-hourly', { cron: '0 * * * *', timezone: 'UTC' }, { from, to });

const worker = new JobWorker(
  nvdSync,
  async (payload, { signal }) => {
    /* … */
  },
  {
    connection: redis,
    service: SERVICE_NAME,
    logger,
    rateLimit: { max: 5, durationMs: 30_000 },
  },
);
await worker.start();
```

`createRedisHealthIndicator(redis)` reports `PING` latency for the health module.

## Where it is used

- **Identity Service** (Phase 1): `PrismaOutboxStore` + `OutboxRelay` publish `identity.user.roles-changed`,
  `identity.user.status-changed` and `identity.session.revoked` (payload schemas in
  `@cve/contracts`), and a BullMQ scheduler ingests Keycloak events into the audit log every minute.
  Its readiness check uses the AMQP connection and Redis `PING`.
- **CVE Service** (Phase 2): `PrismaOutboxStore` + `OutboxRelay` publish `cve.record.created`,
  `cve.record.updated` and `cve.record.deleted` (payload schemas in `@cve/contracts`, see
  [cve-service.md](cve-service.md)). It uses no BullMQ jobs yet.
- **Intelligence Service** (Phase 3): `PrismaOutboxStore` + `OutboxRelay` publish the
  `intelligence.*` observation, KEV, EPSS and sync-run events, and BullMQ job schedulers run each
  source on its cron plus a maintenance job that recovers abandoned runs (see
  [intelligence-service.md](intelligence-service.md)).
- **Asset Service** (Phase 4): the first consumer. It consumes
  `intelligence.cve-observation.recorded` (queue `asset-service.cve-observation-products`) and
  `cve.record.*` (queue `asset-service.cve-record-facts`), with duplicate suppression in a
  `processed_events` inbox table written in the handler's transaction, and publishes
  `asset.vendor.*`, `asset.product.*` and `asset.cve-association.*` through its outbox (see
  [asset-service.md](asset-service.md)).
- **PoC Service** (Phase 5): consumes `cve.record.*` (consumer `cve-record-tracker`) and
  `intelligence.cve-observation.recorded` (consumer `cve-observation-references`), publishes
  `poc.repository.*`, `poc.cve-association.*`, `poc.artifact.*`, `poc.reference.discovered`
  and `poc.discovery-run.*` through its outbox, and runs the BullMQ queues `poc-discovery`,
  `poc-inspection`, `poc-scheduling` and `poc-maintenance` (see [poc-service.md](poc-service.md)).
- The other services do not open RabbitMQ or Redis connections yet; their first producers,
  consumers and jobs arrive with their features.
