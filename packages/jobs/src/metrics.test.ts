import { platformRegistry } from '@cve/metrics';
import { describe, expect, it } from 'vitest';

import { recordJob, registerQueueDepthSource } from './metrics.js';

describe('job metrics', () => {
  it('counts job outcomes per queue', async () => {
    recordJob('intelligence-sync', 'completed');
    recordJob('intelligence-sync', 'retrying');
    const text = await platformRegistry.getSingleMetricAsString('jobs_processed_total');
    expect(text).toContain('jobs_processed_total{queue="intelligence-sync",outcome="completed"} 1');
    expect(text).toContain('jobs_processed_total{queue="intelligence-sync",outcome="retrying"} 1');
  });

  it('reads queue depth at scrape time and skips unreadable queues', async () => {
    const unregister = registerQueueDepthSource('downloads', () =>
      Promise.resolve({ waiting: 3, active: 1, completed: 900, failed: 2 }),
    );
    const unregisterBroken = registerQueueDepthSource('broken', () =>
      Promise.reject(new Error('redis down')),
    );
    const text = await platformRegistry.getSingleMetricAsString('job_queue_jobs');
    expect(text).toContain('job_queue_jobs{queue="downloads",state="waiting"} 3');
    expect(text).toContain('job_queue_jobs{queue="downloads",state="failed"} 2');
    expect(text).not.toContain('state="completed"');
    expect(text).not.toContain('queue="broken"');
    unregister();
    unregisterBroken();
    expect(await platformRegistry.getSingleMetricAsString('job_queue_jobs')).not.toContain(
      'queue="downloads"',
    );
  });
});
