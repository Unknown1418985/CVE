'use client';

import { ASSESSMENT_SORT_FIELDS, CVE_SORT_FIELDS, type CveSummary } from '@cve/contracts';
import { Flame, Radar, ShieldAlert, Skull, Swords } from 'lucide-react';
import type { ReactElement } from 'react';

import { DataTable, type Column, type SortOrder } from '@/components/data/data-table';
import { CveLink } from '@/components/data/links';
import { PageHeader } from '@/components/data/page-header';
import { Pagination } from '@/components/data/pagination';
import { StatCard } from '@/components/data/stat-card';
import { EmptyState, ErrorState } from '@/components/data/states';
import { KevBadge, SeverityBadge } from '@/components/data/status-badges';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useCan } from '@/features/auth/use-me';
import { useCveList } from '@/features/cves/api';
import { ASSESSMENT_COLUMNS } from '@/features/exploits/assessment-columns';
import { useAssessments, useAssessmentStatistics } from '@/features/exploits/api';
import { intValue, useSearchState } from '@/hooks/use-search-state';
import type { QueryParams } from '@/lib/api/client';
import { useApiCount } from '@/lib/api/hooks';
import { formatDate, formatPercent } from '@/lib/format';

const DEFAULTS = { tab: 'kev', page: '1', pageSize: '25', sort: '', order: 'desc' } as const;

const CVE_COLUMNS: readonly Column<CveSummary>[] = [
  {
    id: 'cveId',
    header: 'CVE ID',
    sortField: 'cveId',
    cell: (row) => <CveLink cveId={row.cveId} />,
  },
  {
    id: 'severity',
    header: 'Severity',
    sortField: 'cvssScore',
    cell: (row) => <SeverityBadge severity={row.severity} score={row.cvssScore} />,
  },
  {
    id: 'summary',
    header: 'Summary',
    className: 'min-w-64',
    cell: (row) => (
      <span className="line-clamp-2 text-muted-foreground">{row.title ?? row.description}</span>
    ),
  },
  {
    id: 'epss',
    header: 'EPSS',
    sortField: 'epssScore',
    className: 'text-right',
    cell: (row) => <span className="tabular-nums">{formatPercent(row.epssScore)}</span>,
  },
  {
    id: 'percentile',
    header: 'Percentile',
    className: 'text-right',
    cell: (row) => <span className="tabular-nums">{formatPercent(row.epssPercentile, 1)}</span>,
  },
  { id: 'kev', header: 'KEV', cell: (row) => (row.inKev ? <KevBadge inKev /> : '—') },
  {
    id: 'modified',
    header: 'Modified',
    sortField: 'lastModifiedAt',
    cell: (row) => formatDate(row.lastModifiedAt),
  },
];

interface TabConfig {
  readonly value: string;
  readonly label: string;
  readonly kind: 'cve' | 'assessment';
  readonly query: QueryParams;
  readonly defaultSort: string;
  readonly empty: string;
}

const TABS: readonly TabConfig[] = [
  {
    value: 'kev',
    label: 'Recently added to KEV',
    kind: 'assessment',
    query: { inKev: 'true' },
    defaultSort: 'kevDateAdded',
    empty: 'No CVEs from the KEV catalog have been assessed yet.',
  },
  {
    value: 'epss',
    label: 'Highest EPSS',
    kind: 'cve',
    query: { epssScoreMin: 0.01 },
    defaultSort: 'epssScore',
    empty: 'No EPSS scores have been recorded yet.',
  },
  {
    value: 'itw',
    label: 'Exploited in the wild',
    kind: 'assessment',
    query: { exploitedInTheWild: 'true' },
    defaultSort: 'evaluatedAt',
    empty: 'No CVE is currently assessed as exploited in the wild.',
  },
  {
    value: 'weaponized',
    label: 'Weaponized, not in KEV',
    kind: 'assessment',
    query: { maturity: ['weaponized'], inKev: 'false' },
    defaultSort: 'confidence',
    empty: 'No weaponized exploit outside the KEV catalog.',
  },
  {
    value: 'ransomware',
    label: 'Ransomware campaigns',
    kind: 'assessment',
    query: { knownRansomwareCampaignUse: 'true' },
    defaultSort: 'kevDateAdded',
    empty: 'No CVE with known ransomware campaign use.',
  },
];

function TabTable({
  tab,
  values,
  update,
}: {
  tab: TabConfig;
  values: Record<keyof typeof DEFAULTS, string>;
  update: (patch: Record<string, string | number>) => void;
}): ReactElement {
  const validSorts: readonly string[] =
    tab.kind === 'cve' ? CVE_SORT_FIELDS : ASSESSMENT_SORT_FIELDS;
  const sort = validSorts.includes(values.sort) ? values.sort : tab.defaultSort;
  const order: SortOrder = values.order === 'asc' ? 'asc' : 'desc';
  const paging = {
    page: intValue(values.page, 1),
    pageSize: intValue(values.pageSize, 25),
    sort,
    order,
  };
  const cves = useCveList({ ...tab.query, ...paging }, tab.kind === 'cve');
  const assessments = useAssessments({ ...tab.query, ...paging }, tab.kind === 'assessment');
  const query = tab.kind === 'cve' ? cves : assessments;
  if (query.isError)
    return (
      <ErrorState
        error={query.error}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  const sortProps = {
    sort: { field: sort, order },
    onSortChange: (next: { field: string; order: SortOrder }) => {
      update({ sort: next.field, order: next.order });
    },
  };
  return (
    <div className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4">
      {tab.kind === 'cve' ? (
        <DataTable
          caption={tab.label}
          columns={CVE_COLUMNS}
          rows={cves.data?.data}
          loading={cves.isPending}
          fetching={cves.isFetching}
          getRowKey={(row) => row.id}
          rowHref={(row) => `/cves/${row.cveId}`}
          emptyTitle="Nothing to show"
          emptyDescription={tab.empty}
          {...sortProps}
        />
      ) : (
        <DataTable
          caption={tab.label}
          columns={ASSESSMENT_COLUMNS}
          rows={assessments.data?.data}
          loading={assessments.isPending}
          fetching={assessments.isFetching}
          getRowKey={(row) => row.cveId}
          rowHref={(row) => `/cves/${row.cveId}`}
          emptyTitle="Nothing to show"
          emptyDescription={tab.empty}
          {...sortProps}
        />
      )}
      {query.data === undefined ? null : (
        <Pagination
          meta={query.data.meta}
          onPageChange={(page) => {
            update({ page });
          }}
          onPageSizeChange={(pageSize) => {
            update({ pageSize });
          }}
        />
      )}
    </div>
  );
}

export function ThreatIntelligence(): ReactElement {
  const { values, update } = useSearchState(DEFAULTS);
  const canCve = useCan('cve:read');
  const canExploit = useCan('exploit:read');
  const kev = useApiCount('cves', { kev: 'true' }, canCve === true);
  const ransomware = useApiCount(
    'exploit-assessments',
    { knownRansomwareCampaignUse: 'true' },
    canExploit === true,
  );
  const statistics = useAssessmentStatistics(canExploit === true);
  const tabs = TABS.filter((tab) => (tab.kind === 'cve' ? canCve !== false : canExploit !== false));
  const active = tabs.find((tab) => tab.value === values.tab) ?? tabs[0];

  return (
    <>
      <PageHeader
        title="Threat Intelligence"
        description="Known exploitation (CISA KEV), exploitation probability (FIRST EPSS) and exploit maturity correlated by the platform."
      />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        <StatCard
          label="KEV listed CVEs"
          icon={<Radar className="size-4" aria-hidden="true" />}
          value={kev.data}
          loading={kev.isPending && canCve !== false}
          error={kev.isError || canCve === false}
          href="/cves?kev=true"
        />
        <StatCard
          label="Exploited in the wild"
          icon={<Flame className="size-4" aria-hidden="true" />}
          value={statistics.data?.data.exploitedInTheWild}
          loading={statistics.isPending && canExploit !== false}
          error={statistics.isError || canExploit === false}
        />
        <StatCard
          label="Known ransomware use"
          icon={<Skull className="size-4" aria-hidden="true" />}
          value={ransomware.data}
          loading={ransomware.isPending && canExploit !== false}
          error={ransomware.isError || canExploit === false}
        />
        <StatCard
          label="KEV without public exploit"
          icon={<ShieldAlert className="size-4" aria-hidden="true" />}
          value={statistics.data?.data.kevWithoutPublicExploit}
          loading={statistics.isPending && canExploit !== false}
          error={statistics.isError || canExploit === false}
        />
        <StatCard
          label="Weaponized, not in KEV"
          icon={<Swords className="size-4" aria-hidden="true" />}
          value={statistics.data?.data.weaponizedNotInKev}
          loading={statistics.isPending && canExploit !== false}
          error={statistics.isError || canExploit === false}
        />
      </div>
      {active === undefined ? (
        <EmptyState
          title="Access restricted"
          description="Your role cannot view CVE or exploit intelligence."
        />
      ) : (
        <Tabs
          value={active.value}
          onValueChange={(tab) => {
            update({ tab, sort: '', order: '' });
          }}
        >
          <TabsList>
            {tabs.map((tab) => (
              <TabsTrigger key={tab.value} value={tab.value}>
                {tab.label}
              </TabsTrigger>
            ))}
          </TabsList>
          <TabsContent value={active.value}>
            <TabTable tab={active} values={values} update={update} />
          </TabsContent>
        </Tabs>
      )}
    </>
  );
}
