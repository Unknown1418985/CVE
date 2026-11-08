'use client';

import { sourceStatusSchema, syncRunDetailSchema, syncRunSchema } from '@cve/contracts';
import { z } from 'zod';

import { apiPath, dataSchema, pageSchema, type QueryParams } from '@/lib/api/client';
import { useApiQuery } from '@/lib/api/hooks';

export function useSources(enabled = true) {
  return useApiQuery({ path: 'sources', schema: dataSchema(z.array(sourceStatusSchema)), enabled });
}

export function useSyncRuns(query: QueryParams, enabled = true) {
  return useApiQuery({
    path: 'sync-runs',
    schema: pageSchema(syncRunSchema),
    query,
    enabled,
    keepPrevious: true,
    refetchInterval: 15_000,
  });
}

export function useSyncRun(runId: string | null) {
  return useApiQuery({
    path: apiPath('sync-runs', runId ?? 'none'),
    schema: dataSchema(syncRunDetailSchema),
    enabled: runId !== null,
  });
}
