'use client';

import {
  discoveryRunSchema,
  pocArtifactDetailSchema,
  pocArtifactSchema,
  pocAssociationSchema,
  pocConnectorStatusSchema,
  pocReferenceSchema,
  pocRepositorySchema,
  repositoryCommitSchema,
  verificationEventSchema,
} from '@cve/contracts';
import { z } from 'zod';

import { apiPath, dataSchema, pageSchema, type QueryParams } from '@/lib/api/client';
import { useApiQuery } from '@/lib/api/hooks';

export function usePocRepositories(query: QueryParams, enabled = true) {
  return useApiQuery({
    path: 'poc-repositories',
    schema: pageSchema(pocRepositorySchema),
    query,
    enabled,
    keepPrevious: true,
  });
}

export function usePocRepository(repositoryId: string) {
  return useApiQuery({
    path: apiPath('poc-repositories', repositoryId),
    schema: dataSchema(pocRepositorySchema),
  });
}

export function useRepositoryCommits(repositoryId: string) {
  return useApiQuery({
    path: apiPath('poc-repositories', repositoryId, 'commits'),
    schema: pageSchema(repositoryCommitSchema),
    query: { pageSize: 20 },
  });
}

export function usePocAssociations(query: QueryParams, enabled = true) {
  return useApiQuery({
    path: 'poc-associations',
    schema: pageSchema(pocAssociationSchema),
    query,
    enabled,
    keepPrevious: true,
  });
}

export function usePocArtifacts(query: QueryParams, enabled = true) {
  return useApiQuery({
    path: 'poc-artifacts',
    schema: pageSchema(pocArtifactSchema),
    query,
    enabled,
    keepPrevious: true,
  });
}

export function usePocArtifact(artifactId: string) {
  return useApiQuery({
    path: apiPath('poc-artifacts', artifactId),
    schema: dataSchema(pocArtifactDetailSchema),
  });
}

export function useVerificationHistory(artifactId: string) {
  return useApiQuery({
    path: apiPath('poc-artifacts', artifactId, 'verification-history'),
    schema: dataSchema(z.array(verificationEventSchema)),
  });
}

export function usePocReferences(query: QueryParams, enabled = true) {
  return useApiQuery({
    path: 'poc-references',
    schema: pageSchema(pocReferenceSchema),
    query,
    enabled,
  });
}

export function usePocConnectors(enabled = true) {
  return useApiQuery({
    path: 'poc-connectors',
    schema: dataSchema(z.array(pocConnectorStatusSchema)),
    enabled,
  });
}

export function useDiscoveryRuns(query: QueryParams, enabled = true) {
  return useApiQuery({
    path: 'poc-discovery-runs',
    schema: pageSchema(discoveryRunSchema),
    query,
    enabled,
    keepPrevious: true,
  });
}
