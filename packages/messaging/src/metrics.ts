import { boundedLabel, counter, gauge, histogram, WORK_DURATION_BUCKETS } from '@cve/metrics';

/** Outcome of handling one delivered message. */
export type ConsumeOutcome =
  'processed' | 'duplicate' | 'invalid' | 'retry_scheduled' | 'dead_lettered' | 'requeued';

export const eventsConsumed = () =>
  counter({
    name: 'messaging_events_consumed_total',
    help: 'Domain events delivered to a consumer, by outcome',
    labelNames: ['queue', 'event_type', 'outcome'] as const,
  });

export const eventHandlerDuration = () =>
  histogram({
    name: 'messaging_event_handler_duration_seconds',
    help: 'Time spent in domain event handlers (successful and failed attempts)',
    labelNames: ['queue', 'event_type'] as const,
    buckets: [...WORK_DURATION_BUCKETS],
  });

export const eventsPublished = () =>
  counter({
    name: 'messaging_events_published_total',
    help: 'Domain events published to the broker, by outcome (confirmed or failed)',
    labelNames: ['event_type', 'outcome'] as const,
  });

export const outboxRelayed = () =>
  counter({
    name: 'outbox_events_relayed_total',
    help: 'Outbox records processed by the relay, by outcome (published or failed)',
    labelNames: ['outcome'] as const,
  });

export function recordConsumed(
  queue: string,
  eventType: string | undefined,
  outcome: ConsumeOutcome,
) {
  eventsConsumed().inc({
    queue: boundedLabel(queue),
    event_type: boundedLabel(eventType),
    outcome,
  });
}

/** Pending outbox statistics reported by a store at scrape time. */
export interface OutboxBacklog {
  /** Unpublished records. */
  readonly pending: number;
  /** Age of the oldest unpublished record, or null without a backlog. */
  readonly oldestPendingAgeSeconds: number | null;
}

const backlogSources = new Set<() => Promise<OutboxBacklog>>();

/**
 * Registers a backlog source (one per running relay). The gauges query every source when
 * Prometheus scrapes, so the outbox table is counted every scrape interval, not every poll.
 */
export function registerOutboxBacklogSource(source: () => Promise<OutboxBacklog>): () => void {
  backlogSources.add(source);
  ensureBacklogGauges();
  return () => {
    backlogSources.delete(source);
  };
}

let backlog: Promise<OutboxBacklog> | undefined;
function collectBacklog(): Promise<OutboxBacklog> {
  backlog ??= Promise.all(
    // A failing source (database briefly unavailable) is left out instead of failing the scrape.
    [...backlogSources].map((source) => source().catch(() => null)),
  )
    .then((results) =>
      results
        .filter((result): result is OutboxBacklog => result !== null)
        .reduce<OutboxBacklog>(
          (total, next) => ({
            pending: total.pending + next.pending,
            oldestPendingAgeSeconds:
              next.oldestPendingAgeSeconds === null
                ? total.oldestPendingAgeSeconds
                : Math.max(total.oldestPendingAgeSeconds ?? 0, next.oldestPendingAgeSeconds),
          }),
          { pending: 0, oldestPendingAgeSeconds: null },
        ),
    )
    .finally(() => {
      setTimeout(() => {
        backlog = undefined;
      }, 1_000).unref();
    });
  return backlog;
}

function ensureBacklogGauges(): void {
  gauge({
    name: 'outbox_pending_events',
    help: 'Unpublished records in the service outbox',
    labelNames: [] as const,
    async collect() {
      if (backlogSources.size === 0) return;
      this.set((await collectBacklog()).pending);
    },
  });
  gauge({
    name: 'outbox_oldest_pending_age_seconds',
    help: 'Age of the oldest unpublished outbox record (0 without a backlog)',
    labelNames: [] as const,
    async collect() {
      if (backlogSources.size === 0) return;
      this.set((await collectBacklog()).oldestPendingAgeSeconds ?? 0);
    },
  });
}
