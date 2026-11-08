'use client';

import {
  cveRecordSchema,
  cveSummarySchema,
  cvssMetricSchema,
  epssObservationSchema,
} from '@cve/contracts';
import { z } from 'zod';

import { apiPath, dataSchema, pageSchema, type QueryParams } from '@/lib/api/client';
import { useApiQuery } from '@/lib/api/hooks';

export const cvePageSchema = pageSchema(cveSummarySchema);

export function useCveList(query: QueryParams, enabled = true) {
  return useApiQuery({ path: 'cves', schema: cvePageSchema, query, enabled, keepPrevious: true });
}

export function useCve(cveId: string) {
  return useApiQuery({ path: apiPath('cves', cveId), schema: dataSchema(cveRecordSchema) });
}

export function useCvssHistory(cveId: string) {
  return useApiQuery({
    path: apiPath('cves', cveId, 'cvss-history'),
    schema: dataSchema(z.array(cvssMetricSchema)),
  });
}

export function useEpssHistory(cveId: string) {
  return useApiQuery({
    path: apiPath('cves', cveId, 'epss-history'),
    schema: pageSchema(epssObservationSchema),
    query: { pageSize: 100 },
  });
}

/** `YYYY-MM-DD` from a date input to the inclusive UTC bounds the API expects. */
export function dayStart(value: string): string | undefined {
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T00:00:00Z` : undefined;
}

export function dayEnd(value: string): string | undefined {
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T23:59:59Z` : undefined;
}
