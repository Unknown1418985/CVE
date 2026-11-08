'use client';

import { RECORD_SEVERITIES } from '@cve/contracts';
import { useRouter } from 'next/navigation';
import type { ReactElement } from 'react';

import { BarChartView } from '@/components/data/bar-chart';
import { EmptyState, ErrorState, LoadingState } from '@/components/data/states';
import { SEVERITY_COLORS } from '@/components/data/status-badges';
import { buildQueryString, type QueryParams } from '@/lib/api/client';
import { useApiCounts } from '@/lib/api/hooks';
import { humanize } from '@/lib/format';

/** CVE counts per severity from the CVE Service, optionally within a filter scope. */
export function SeverityDistribution({ scope = {} }: { scope?: QueryParams }): ReactElement {
  const router = useRouter();
  const result = useApiCounts(
    'cves',
    RECORD_SEVERITIES.map((severity) => ({ ...scope, severity })),
  );
  if (result.isPending) return <LoadingState rows={4} />;
  if (result.error !== null) return <ErrorState error={result.error} onRetry={result.refetch} />;
  const data = RECORD_SEVERITIES.map((severity, index) => ({
    key: severity,
    label: humanize(severity),
    value: result.counts[index] ?? 0,
    color: SEVERITY_COLORS[severity],
  }));
  if (data.every((datum) => datum.value === 0)) {
    return (
      <EmptyState
        title="No CVE records"
        description="Counts appear once the CVE Service holds records from the configured sources."
      />
    );
  }
  return (
    <BarChartView
      data={data}
      valueLabel="CVEs"
      onSelect={(datum) => {
        router.push(`/cves${buildQueryString({ ...scope, severity: datum.key })}`);
      }}
    />
  );
}
