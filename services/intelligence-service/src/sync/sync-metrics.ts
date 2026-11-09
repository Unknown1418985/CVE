import { boundedLabel, counter, gauge, histogram, WORK_DURATION_BUCKETS } from '@cve/metrics';

const syncRuns = () =>
  counter({
    name: 'source_sync_runs_total',
    help: 'Synchronisation runs per intelligence source by final status',
    labelNames: ['source', 'status'] as const,
  });

const syncDuration = () =>
  histogram({
    name: 'source_sync_duration_seconds',
    help: 'Duration of finished synchronisation runs',
    labelNames: ['source', 'status'] as const,
    buckets: [...WORK_DURATION_BUCKETS, 1_800, 3_600],
  });

const lastSuccess = () =>
  gauge({
    name: 'source_sync_last_success_timestamp_seconds',
    help: 'Unix time of the last successful synchronisation run observed by this process',
    labelNames: ['source'] as const,
  });

export function recordSyncRun(
  source: string,
  status: 'succeeded' | 'failed',
  durationSeconds: number,
  finishedAt: Date,
): void {
  const labels = { source: boundedLabel(source), status };
  syncRuns().inc(labels);
  syncDuration().observe(labels, Math.max(0, durationSeconds));
  if (status === 'succeeded') {
    lastSuccess().set({ source: labels.source }, Math.floor(finishedAt.getTime() / 1000));
  }
}
