import { boundedLabel, counter, gauge, histogram, WORK_DURATION_BUCKETS } from '@cve/metrics';

export type JobOutcome = 'completed' | 'retrying' | 'failed' | 'stalled';

export const jobsFinished = () =>
  counter({
    name: 'jobs_processed_total',
    help: 'Background job attempts by outcome (completed, retrying, failed permanently, stalled)',
    labelNames: ['queue', 'outcome'] as const,
  });

export const jobDuration = () =>
  histogram({
    name: 'job_duration_seconds',
    help: 'Duration of successful background job attempts',
    labelNames: ['queue'] as const,
    buckets: [...WORK_DURATION_BUCKETS],
  });

export function recordJob(queue: string, outcome: JobOutcome): void {
  jobsFinished().inc({ queue: boundedLabel(queue), outcome });
}

type CountsSource = () => Promise<Record<string, number>>;
const queues = new Map<string, CountsSource>();

/**
 * Registers a queue whose job counts are read from Redis when Prometheus scrapes
 * (`job_queue_jobs{queue,state}`). A queue that cannot be read is left out of that scrape.
 */
export function registerQueueDepthSource(queue: string, source: CountsSource): () => void {
  queues.set(queue, source);
  gauge({
    name: 'job_queue_jobs',
    help: 'Jobs per queue and state (waiting, active, delayed, prioritized, failed)',
    labelNames: ['queue', 'state'] as const,
    async collect() {
      this.reset();
      await Promise.all(
        [...queues].map(async ([name, read]) => {
          const counts = await read().catch(() => null);
          if (counts === null) return;
          for (const [state, value] of Object.entries(counts)) {
            if (state === 'completed') continue; // retained history, not backlog
            this.set({ queue: boundedLabel(name), state: boundedLabel(state) }, value);
          }
        }),
      );
    },
  });
  return () => {
    if (queues.get(queue) === source) queues.delete(queue);
  };
}
