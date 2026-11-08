'use client';

import {
  triggerCatalogSyncResponseSchema,
  triggerSyncResponseSchema,
  type ExploitCatalogConnector,
  type IntelligenceSource,
} from '@cve/contracts';
import { toast } from 'sonner';

import { apiPath, dataSchema, newIdempotencyKey } from '@/lib/api/client';
import { useApiMutation } from '@/lib/api/hooks';

function queuedMessage(queued: boolean): string {
  return queued ? 'Synchronisation queued' : 'A synchronisation for this source is already queued or running';
}

/** Queues an intelligence source sync. `fresh` ignores the checkpoint of a recent failed run. */
export function useTriggerSourceSync() {
  return useApiMutation({
    schema: dataSchema(triggerSyncResponseSchema),
    request: (input: { source: IntelligenceSource; fresh: boolean }) => ({
      path: apiPath('sources', input.source, 'sync'),
      method: 'POST',
      body: { fresh: input.fresh },
      headers: { 'idempotency-key': newIdempotencyKey() },
    }),
    invalidate: ['sources', 'sync-runs'],
    onSuccess: (data) => {
      toast.success(queuedMessage(data.data.queued));
    },
  });
}

export function useRetrySyncRun() {
  return useApiMutation({
    schema: dataSchema(triggerSyncResponseSchema),
    request: (input: { runId: string }) => ({
      path: apiPath('sync-runs', input.runId, 'retry'),
      method: 'POST',
    }),
    invalidate: ['sources', 'sync-runs'],
    onSuccess: (data) => {
      toast.success(data.data.queued ? 'Retry queued from the run checkpoint' : 'A synchronisation is already queued');
    },
  });
}

export function useTriggerCatalogSync() {
  return useApiMutation({
    schema: dataSchema(triggerCatalogSyncResponseSchema),
    request: (input: { connector: ExploitCatalogConnector }) => ({
      path: 'exploit-sync-runs',
      method: 'POST',
      body: { connector: input.connector },
      headers: { 'idempotency-key': newIdempotencyKey() },
    }),
    invalidate: ['exploit-sources', 'exploit-sync-runs'],
    onSuccess: (data) => {
      toast.success(queuedMessage(data.data.queued));
    },
  });
}
