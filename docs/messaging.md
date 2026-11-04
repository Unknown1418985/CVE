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
(`claimDue` should use `SELECT … FOR UPDATE SKIP LOCKED`); the first implementation arrives with
the first event-producing service (Phase 2).

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

## Not wired into the services yet

The packages are complete and tested against live brokers, but the service skeletons do not open
RabbitMQ or Redis connections yet: the first producers, consumers and jobs (and the protocol-level
health indicators that replace today's TCP checks) are added with the features that need them,
starting in Phase 2.
