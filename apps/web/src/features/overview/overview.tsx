'use client';

import { platformHealthSchema, type CveSummary } from '@cve/contracts';
import { Activity, Bug, Lock, Radar, ShieldAlert, TrendingUp } from 'lucide-react';
import type { ReactElement } from 'react';

import { ChartCard } from '@/components/data/chart-card';
import { DataTable, type Column } from '@/components/data/data-table';
import { CveLink, InternalLink } from '@/components/data/links';
import { PageHeader, Section } from '@/components/data/page-header';
import { StatCard } from '@/components/data/stat-card';
import { EmptyState, ErrorState, QueryState } from '@/components/data/states';
import {
  EnabledBadge,
  KevBadge,
  RunStatusBadge,
  SeverityBadge,
} from '@/components/data/status-badges';
import { HealthStatusBadge } from '@/components/health-status-badge';
import { useCan } from '@/features/auth/use-me';
import { useSources } from '@/features/data-sources/api';
import { useAssessmentStatistics } from '@/features/exploits/api';
import { useCveList } from '@/features/cves/api';
import { SeverityDistribution } from '@/features/cves/severity-distribution';
import { dataSchema } from '@/lib/api/client';
import { useApiCount, useApiQuery } from '@/lib/api/hooks';
import { formatDate, formatPercent, formatRelative, humanize } from '@/lib/format';

const RECENT_COLUMNS: readonly Column<CveSummary>[] = [
  { id: 'cveId', header: 'CVE ID', cell: (row) => <CveLink cveId={row.cveId} /> },
  {
    id: 'severity',
    header: 'Severity',
    cell: (row) => <SeverityBadge severity={row.severity} score={row.cvssScore} />,
  },
  {
    id: 'summary',
    header: 'Summary',
    className: 'min-w-64',
    cell: (row) => (
      <span className="line-clamp-1 text-muted-foreground">{row.title ?? row.description}</span>
    ),
  },
  {
    id: 'epss',
    header: 'EPSS',
    className: 'text-right',
    cell: (row) => <span className="tabular-nums">{formatPercent(row.epssScore)}</span>,
  },
  { id: 'kev', header: 'KEV', cell: (row) => (row.inKev ? <KevBadge inKev /> : '—') },
  { id: 'published', header: 'Published', cell: (row) => formatDate(row.publishedAt) },
];

function PlatformServices(): ReactElement {
  const query = useApiQuery({
    path: 'health/services',
    schema: dataSchema(platformHealthSchema),
    refetchInterval: 30_000,
  });
  return (
    <Section
      title="Platform services"
      description="Readiness reported by each service through the API Gateway."
      actions={
        query.data === undefined ? undefined : <HealthStatusBadge status={query.data.data.status} />
      }
    >
      <QueryState query={query}>
        {(data) => (
          <ul className="grid gap-2 sm:grid-cols-2">
            {data.data.services.map((service) => (
              <li
                key={service.service}
                className="flex items-center justify-between gap-2 rounded-md border border-border px-3 py-2"
              >
                <div className="min-w-0">
                  <p className="text-sm font-medium">{humanize(service.service)}</p>
                  {service.message === undefined ? null : (
                    <p className="truncate text-xs text-muted-foreground">{service.message}</p>
                  )}
                </div>
                <HealthStatusBadge status={service.status} />
              </li>
            ))}
          </ul>
        )}
      </QueryState>
    </Section>
  );
}

function SourceStatus(): ReactElement | null {
  const can = useCan('data-source:read');
  const query = useSources(can === true);
  if (can !== true) return null;
  return (
    <Section
      title="Intelligence sources"
      description="Synchronisation state reported by the Intelligence Service."
      actions={<InternalLink href="/data-sources">All data sources</InternalLink>}
    >
      <QueryState
        query={query}
        isEmpty={(data) => data.data.length === 0}
        empty={<EmptyState title="No sources configured" />}
      >
        {(data) => (
          <ul className="flex flex-col divide-y divide-border">
            {data.data.map((source) => (
              <li
                key={source.source}
                className="flex flex-wrap items-center justify-between gap-2 py-2"
              >
                <div>
                  <p className="text-sm font-medium">{source.name}</p>
                  <p className="text-xs text-muted-foreground">
                    Last success {formatRelative(source.state.lastSuccessAt)}
                    {source.state.consecutiveFailures > 0
                      ? ` · ${source.state.consecutiveFailures} consecutive failures`
                      : ''}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <EnabledBadge enabled={source.enabled} />
                  <RunStatusBadge
                    status={source.state.running ? 'running' : source.state.lastRunStatus}
                  />
                </div>
              </li>
            ))}
          </ul>
        )}
      </QueryState>
    </Section>
  );
}

export function Overview(): ReactElement {
  const canCve = useCan('cve:read');
  const canExploit = useCan('exploit:read');
  const canDownloads = useCan('quarantine:read');
  const total = useApiCount('cves', {}, canCve === true);
  const critical = useApiCount('cves', { severity: 'critical' }, canCve === true);
  const kev = useApiCount('cves', { kev: 'true' }, canCve === true);
  const highEpss = useApiCount('cves', { epssScoreMin: 0.1 }, canCve === true);
  const statistics = useAssessmentStatistics(canExploit === true);
  const quarantined = useApiCount(
    'download-artifacts',
    { lifecycleStatus: 'quarantined' },
    canDownloads === true,
  );
  const recent = useCveList({ pageSize: 8, sort: 'publishedAt', order: 'desc' }, canCve === true);

  return (
    <>
      <PageHeader
        title="Overview"
        description="Live counts from the platform services. Every number links to the records behind it."
      />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {canCve === false ? null : (
          <>
            <StatCard
              label="CVE records"
              icon={<Bug className="size-4" aria-hidden="true" />}
              value={total.data}
              loading={total.isPending}
              error={total.isError}
              href="/cves"
            />
            <StatCard
              label="Critical"
              icon={<ShieldAlert className="size-4" aria-hidden="true" />}
              value={critical.data}
              loading={critical.isPending}
              error={critical.isError}
              href="/cves?severity=critical"
            />
            <StatCard
              label="In CISA KEV"
              icon={<Radar className="size-4" aria-hidden="true" />}
              value={kev.data}
              loading={kev.isPending}
              error={kev.isError}
              href="/cves?kev=true"
            />
            <StatCard
              label="EPSS ≥ 10%"
              icon={<TrendingUp className="size-4" aria-hidden="true" />}
              value={highEpss.data}
              loading={highEpss.isPending}
              error={highEpss.isError}
              href="/cves?epssScoreMin=0.1&sort=epssScore"
            />
          </>
        )}
        {canExploit === true ? (
          <StatCard
            label="Exploited in the wild"
            icon={<Activity className="size-4" aria-hidden="true" />}
            value={statistics.data?.data.exploitedInTheWild}
            loading={statistics.isPending}
            error={statistics.isError}
            href="/exploits?exploitedInTheWild=true"
          />
        ) : null}
        {canDownloads === true ? (
          <StatCard
            label="Quarantined artifacts"
            icon={<Lock className="size-4" aria-hidden="true" />}
            value={quarantined.data}
            loading={quarantined.isPending}
            error={quarantined.isError}
            href="/downloads?tab=artifacts&lifecycleStatus=quarantined"
          />
        ) : null}
      </div>
      {canCve === false ? null : (
        <div className="grid gap-6 xl:grid-cols-5">
          <div className="xl:col-span-2">
            <ChartCard
              title="CVEs by severity"
              description="Derived from each record's preferred current CVSS metric. Select a bar to open the list."
            >
              <SeverityDistribution />
            </ChartCard>
          </div>
          <div className="xl:col-span-3">
            <Section
              title="Recently published"
              actions={<InternalLink href="/cves">Open CVE Explorer</InternalLink>}
            >
              {recent.isError ? (
                <ErrorState
                  error={recent.error}
                  onRetry={() => {
                    void recent.refetch();
                  }}
                />
              ) : (
                <DataTable
                  caption="Recently published CVEs"
                  columns={RECENT_COLUMNS}
                  rows={recent.data?.data}
                  loading={recent.isPending}
                  getRowKey={(row) => row.id}
                  rowHref={(row) => `/cves/${row.cveId}`}
                  emptyTitle="No CVE records yet"
                />
              )}
            </Section>
          </div>
        </div>
      )}
      <div className="grid gap-6 xl:grid-cols-2">
        <PlatformServices />
        <SourceStatus />
      </div>
    </>
  );
}
