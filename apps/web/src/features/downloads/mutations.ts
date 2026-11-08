'use client';

import {
  createDownloadResponseSchema,
  downloadArtifactSchema,
  downloadRequestSchema,
  type ArtifactLifecycleStatus,
} from '@cve/contracts';
import { toast } from 'sonner';
import { z } from 'zod';

import { apiPath, dataSchema } from '@/lib/api/client';
import { useApiMutation } from '@/lib/api/hooks';
import { humanize } from '@/lib/format';

import { ifMatch } from '@/features/pocs/mutations';

const INVALIDATE_REQUESTS = ['download-requests'] as const;
const INVALIDATE_ARTIFACTS = ['download-artifacts', 'poc-artifacts'] as const;

export interface ScheduleDownloadInput {
  readonly url: string;
  readonly cveIds: readonly string[];
  readonly priority: number;
  readonly scheduledFor: string | null;
  readonly reason: string;
}

/** Schedules a download by URL. The service only accepts URLs an enabled source recognises. */
export function useScheduleDownload() {
  return useApiMutation({
    schema: dataSchema(createDownloadResponseSchema),
    request: (input: ScheduleDownloadInput) => ({
      path: 'download-requests',
      method: 'POST',
      body: {
        url: input.url,
        cveIds: input.cveIds,
        priority: input.priority,
        ...(input.scheduledFor === null ? {} : { scheduledFor: input.scheduledFor }),
        reason: input.reason === '' ? null : input.reason,
      },
    }),
    invalidate: INVALIDATE_REQUESTS,
    onSuccess: (data) => {
      toast.success(
        data.data.created
          ? 'Download scheduled. The file will land in quarantine and be scanned.'
          : 'This URL was already requested; showing the existing request.',
      );
    },
  });
}

export function useRetryDownload() {
  return useApiMutation({
    schema: dataSchema(downloadRequestSchema),
    request: (input: { id: string; version: number }) => ({
      path: apiPath('download-requests', input.id, 'retry'),
      method: 'POST',
      headers: ifMatch(input.version),
    }),
    invalidate: INVALIDATE_REQUESTS,
    onSuccess: () => {
      toast.success('Download queued again');
    },
  });
}

export function useCancelDownload() {
  return useApiMutation({
    schema: dataSchema(downloadRequestSchema),
    request: (input: { id: string; version: number }) => ({
      path: apiPath('download-requests', input.id, 'cancel'),
      method: 'POST',
      headers: ifMatch(input.version),
    }),
    invalidate: INVALIDATE_REQUESTS,
    onSuccess: () => {
      toast.success('Download cancelled');
    },
  });
}

export function useChangeLifecycle() {
  return useApiMutation({
    schema: dataSchema(downloadArtifactSchema),
    request: (input: {
      id: string;
      version: number;
      status: ArtifactLifecycleStatus;
      reason: string;
    }) => ({
      path: apiPath('download-artifacts', input.id, 'lifecycle'),
      method: 'POST',
      body: { status: input.status, reason: input.reason },
      headers: ifMatch(input.version),
    }),
    invalidate: INVALIDATE_ARTIFACTS,
    onSuccess: (data) => {
      toast.success(`Artifact ${humanize(data.data.lifecycleStatus).toLowerCase()}`);
    },
  });
}

export function useRescanArtifact() {
  return useApiMutation({
    schema: dataSchema(z.object({ queued: z.boolean() })),
    request: (input: { id: string; reason: string }) => ({
      path: apiPath('download-artifacts', input.id, 'rescan'),
      method: 'POST',
      body: { reason: input.reason },
    }),
    invalidate: INVALIDATE_ARTIFACTS,
    onSuccess: (data) => {
      toast.success(
        data.data.queued ? 'Rescan queued' : 'A scan is already queued for this artifact',
      );
    },
  });
}

/** Same-origin BFF URL for a released artifact; the proxy forces an opaque attachment. */
export function artifactContentUrl(artifactId: string): string {
  return `/bff/api/v1/${apiPath('download-artifacts', artifactId, 'content')}`;
}
