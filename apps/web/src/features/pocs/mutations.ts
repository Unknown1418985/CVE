'use client';

import {
  createDownloadResponseSchema,
  pocArtifactSchema,
  pocAssociationSchema,
  triggerDiscoveryResponseSchema,
  type ArtifactVerificationStatus,
  type AssociationReviewStatus,
} from '@cve/contracts';
import { toast } from 'sonner';

import { apiPath, dataSchema, newIdempotencyKey } from '@/lib/api/client';
import { useApiMutation } from '@/lib/api/hooks';

/** `If-Match` with the version the user saw, so concurrent edits fail instead of overwriting. */
export function ifMatch(version: number): Record<string, string> {
  return { 'if-match': `"${version}"` };
}

export function useReviewAssociation() {
  return useApiMutation({
    schema: dataSchema(pocAssociationSchema),
    request: (input: { id: string; version: number; reviewStatus: AssociationReviewStatus; note: string }) => ({
      path: apiPath('poc-associations', input.id),
      method: 'PATCH',
      body: { reviewStatus: input.reviewStatus, note: input.note === '' ? null : input.note },
      headers: ifMatch(input.version),
    }),
    invalidate: ['poc-associations', 'poc-repositories'],
    onSuccess: (data) => {
      toast.success(`Association with ${data.data.cveId} marked ${data.data.reviewStatus}`);
    },
  });
}

export function useChangeVerification() {
  return useApiMutation({
    schema: dataSchema(pocArtifactSchema),
    request: (input: { id: string; version: number; status: ArtifactVerificationStatus; reason: string }) => ({
      path: apiPath('poc-artifacts', input.id, 'verification'),
      method: 'POST',
      body: { status: input.status, reason: input.reason },
      headers: ifMatch(input.version),
    }),
    invalidate: ['poc-artifacts'],
    onSuccess: (data) => {
      toast.success(`Verification status changed to ${data.data.verificationStatus}`);
    },
  });
}

export function useTriggerDiscovery() {
  return useApiMutation({
    schema: dataSchema(triggerDiscoveryResponseSchema),
    request: (
      input:
        | { mode: 'repository'; repositoryId: string }
        | { mode: 'cve'; cveId: string }
        | { mode: 'recent' },
    ) => ({
      path: 'poc-discovery-runs',
      method: 'POST',
      body: { connector: 'github', ...input },
      headers: { 'idempotency-key': newIdempotencyKey() },
    }),
    invalidate: ['poc-discovery-runs'],
    onSuccess: (data) => {
      toast.success(data.data.queued ? 'Discovery job queued' : 'An identical discovery job is already queued');
    },
  });
}

export function useScheduleArtifactDownload() {
  return useApiMutation({
    schema: dataSchema(createDownloadResponseSchema),
    request: (input: { pocArtifactId: string; reason: string }) => ({
      path: 'download-requests',
      method: 'POST',
      body: { pocArtifactId: input.pocArtifactId, reason: input.reason === '' ? null : input.reason },
    }),
    invalidate: ['download-requests'],
    onSuccess: (data) => {
      toast.success(data.data.created ? 'Download scheduled. The file will land in quarantine.' : 'This artifact was already requested.');
    },
  });
}
