'use client';

import {
  downloadArtifactDetailSchema,
  downloadArtifactSchema,
  downloadRequestDetailSchema,
  downloadRequestSchema,
  downloadSourceStatusSchema,
  lifecycleEventSchema,
  scanResultSchema,
} from '@cve/contracts';
import { z } from 'zod';

import { apiPath, dataSchema, pageSchema, type QueryParams } from '@/lib/api/client';
import { useApiQuery } from '@/lib/api/hooks';

export function useDownloadSources(enabled = true) {
  return useApiQuery({
    path: 'download-sources',
    schema: dataSchema(z.array(downloadSourceStatusSchema)),
    enabled,
  });
}

export function useDownloadRequests(query: QueryParams, enabled = true) {
  return useApiQuery({
    path: 'download-requests',
    schema: pageSchema(downloadRequestSchema),
    query,
    enabled,
    keepPrevious: true,
    refetchInterval: 10_000,
  });
}

export function useDownloadRequest(requestId: string) {
  return useApiQuery({
    path: apiPath('download-requests', requestId),
    schema: dataSchema(downloadRequestDetailSchema),
  });
}

export function useDownloadArtifacts(query: QueryParams, enabled = true) {
  return useApiQuery({
    path: 'download-artifacts',
    schema: pageSchema(downloadArtifactSchema),
    query,
    enabled,
    keepPrevious: true,
  });
}

export function useDownloadArtifact(artifactId: string) {
  return useApiQuery({
    path: apiPath('download-artifacts', artifactId),
    schema: dataSchema(downloadArtifactDetailSchema),
  });
}

export function useArtifactScans(artifactId: string, enabled = true) {
  return useApiQuery({
    path: apiPath('download-artifacts', artifactId, 'scans'),
    schema: dataSchema(z.array(scanResultSchema)),
    enabled,
  });
}

export function useLifecycleHistory(artifactId: string) {
  return useApiQuery({
    path: apiPath('download-artifacts', artifactId, 'lifecycle-history'),
    schema: dataSchema(z.array(lifecycleEventSchema)),
  });
}
