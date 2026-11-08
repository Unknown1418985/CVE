'use client';

import {
  ARTIFACT_LIFECYCLE_STATUSES,
  ARTIFACT_SCAN_STATUSES,
  DOWNLOAD_REQUEST_STATUSES,
  DOWNLOAD_SOURCES,
  type DownloadArtifact,
  type DownloadRequest,
  type DownloadSourceStatus,
} from '@cve/contracts';
import { Ban, CheckCircle2, Clock, Lock, ShieldX, Unlock } from 'lucide-react';
import type { ReactElement } from 'react';

import { DataTable, type Column } from '@/components/data/data-table';
import { FilterBar, MultiSelectFilter, SearchFilter, SelectFilter, optionsFrom } from '@/components/data/filters';
import { CveLink, ExternalLink, InternalLink } from '@/components/data/links';
import { PageHeader, Section } from '@/components/data/page-header';
import {
  CveIdFilter,
  ResultsPanel,
  cveFilterValue,
  pagingFromValues,
  sortFromValues,
  type UpdateSearch,
} from '@/components/data/results';
import { StatCard } from '@/components/data/stat-card';
import { EmptyState, QueryState } from '@/components/data/states';
import { ArtifactSecurityStatus, DownloadStatusBadge, EnabledBadge } from '@/components/data/status-badges';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useCan } from '@/features/auth/use-me';
import { listValue, useSearchState } from '@/hooks/use-search-state';
import type { QueryParams } from '@/lib/api/client';
import { useApiCounts } from '@/lib/api/hooks';
import { formatBytes, formatDateTime, formatRelative, humanize, shortHash } from '@/lib/format';

import { useDownloadArtifacts, useDownloadRequests, useDownloadSources } from './api';
import { ScheduleDownloadForm } from './schedule-form';

const DEFAULTS = {
  tab: 'requests',
  status: '',
  source: '',
  trigger: '',
  cveId: '',
  lifecycleStatus: '',
  scanStatus: '',
  sha256: '',
  sort: '',
  order: '',
  page: '1',
  pageSize: '25',
} as const;
type Values = Record<keyof typeof DEFAULTS, string>;

const SHA256 = /^[0-9a-f]{64}$/;
const TABS = ['requests', 'artifacts', 'sources'] as const;

function CveList({ cveIds }: { cveIds: readonly string[] }): ReactElement {
  if (cveIds.length === 0) return <span className="text-muted-foreground">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {cveIds.slice(0, 2).map((cveId) => <CveLink key={cveId} cveId={cveId} className="text-xs" />)}
      {cveIds.length > 2 ? <span className="text-xs text-muted-foreground">+{cveIds.length - 2}</span> : null}
    </div>
  );
}

export const REQUEST_COLUMNS: readonly Column<DownloadRequest>[] = [
  {
    id: 'source',
    header: 'Request',
    className: 'min-w-64',
    cell: (row) => (
      <div className="flex flex-col gap-0.5">
        <InternalLink href={`/downloads/requests/${row.id}`} className="font-medium">
          {row.sourceRepository ?? humanize(row.source)}
          {row.commitSha === null ? null : <span className="font-mono-id text-xs text-muted-foreground"> @{shortHash(row.commitSha, 10)}</span>}
        </InternalLink>
        <span className="line-clamp-1 max-w-md break-all font-mono-id text-xs text-muted-foreground">{row.sourceUrl}</span>
      </div>
    ),
  },
  { id: 'status', header: 'Status', cell: (row) => (
    <div className="flex flex-col gap-1">
      <DownloadStatusBadge status={row.status} />
      {row.errorCode === null ? null : <span className="text-xs text-muted-foreground">{humanize(row.errorCode)}</span>}
    </div>
  ) },
  { id: 'cves', header: 'CVEs', cell: (row) => <CveList cveIds={row.cveIds} /> },
  { id: 'attempts', header: 'Attempts', className: 'text-right', cell: (row) => <span className="tabular-nums">{row.attempts} / {row.maxAttempts}</span> },
  { id: 'trigger', header: 'Trigger', cell: (row) => (row.trigger === 'manual' ? `Manual${row.requestedBy === null ? '' : ` · ${row.requestedBy}`}` : 'Automatic') },
  { id: 'scheduled', header: 'Scheduled', sortField: 'scheduledFor', cell: (row) => <span title={formatDateTime(row.scheduledFor)}>{formatRelative(row.scheduledFor)}</span> },
  { id: 'created', header: 'Created', sortField: 'createdAt', cell: (row) => formatDateTime(row.createdAt) },
];

export const DOWNLOAD_ARTIFACT_COLUMNS: readonly Column<DownloadArtifact>[] = [
  {
    id: 'artifact',
    header: 'Artifact',
    className: 'min-w-64',
    cell: (row) => (
      <div className="flex flex-col gap-0.5">
        <InternalLink href={`/downloads/artifacts/${row.id}`} className="font-mono-id text-xs">sha256:{shortHash(row.sha256, 16)}</InternalLink>
        <span className="line-clamp-1 text-xs text-muted-foreground">{row.sourceRepository ?? row.sourceUrl}</span>
      </div>
    ),
  },
  { id: 'security', header: 'Security status', cell: (row) => <ArtifactSecurityStatus lifecycle={row.lifecycleStatus} scan={row.scanStatus} verification={row.verificationStatus} /> },
  {
    id: 'type',
    header: 'Detected type',
    cell: (row) => (
      <div className="flex flex-wrap gap-1">
        <Badge variant="muted">{humanize(row.detectedType)}</Badge>
        {row.riskIndicators.map((indicator) => <Badge key={indicator} variant="warning">{humanize(indicator)}</Badge>)}
      </div>
    ),
  },
  { id: 'size', header: 'Size', sortField: 'sizeBytes', className: 'text-right', cell: (row) => <span className="tabular-nums">{formatBytes(row.sizeBytes)}</span> },
  { id: 'cves', header: 'CVEs', cell: (row) => <CveList cveIds={row.cveIds} /> },
  { id: 'scanned', header: 'Last scan', sortField: 'lastScannedAt', cell: (row) => (row.lastScannedAt === null ? 'Never' : formatDateTime(row.lastScannedAt)) },
  { id: 'downloaded', header: 'Downloaded', sortField: 'downloadedAt', cell: (row) => formatDateTime(row.downloadedAt) },
];

function RequestsTab({ values, update }: { values: Values; update: UpdateSearch }): ReactElement {
  const sort = sortFromValues(values, ['createdAt', 'scheduledFor', 'finishedAt'], 'createdAt');
  const statuses = listValue(values.status);
  const query = useDownloadRequests({
    status: statuses,
    source: values.source,
    trigger: values.trigger,
    cveId: cveFilterValue(values.cveId),
    sort: sort.field,
    order: sort.order,
    ...pagingFromValues(values),
  });
  return (
    <div className="flex flex-col gap-4">
      <FilterBar>
        <MultiSelectFilter label="Status" values={statuses} options={optionsFrom(DOWNLOAD_REQUEST_STATUSES, humanize)}
          onChange={(status) => { update({ status }); }} />
        <SelectFilter id="request-source" label="Source" value={values.source} options={optionsFrom(DOWNLOAD_SOURCES, humanize)}
          onChange={(source) => { update({ source }); }} />
        <SelectFilter id="request-trigger" label="Trigger" value={values.trigger}
          options={[{ value: 'manual', label: 'Manual' }, { value: 'event', label: 'Automatic' }]}
          onChange={(trigger) => { update({ trigger }); }} />
        <CveIdFilter value={values.cveId} update={update} />
      </FilterBar>
      <ResultsPanel query={query} update={update}>
        <DataTable caption="Download requests" columns={REQUEST_COLUMNS} rows={query.data?.data} loading={query.isPending}
          fetching={query.isFetching} getRowKey={(row) => row.id} rowHref={(row) => `/downloads/requests/${row.id}`}
          sort={sort} onSortChange={(next) => { update({ sort: next.field, order: next.order }); }}
          emptyTitle="No download requests" emptyDescription="Nothing has been scheduled with these filters." />
      </ResultsPanel>
    </div>
  );
}

function ArtifactsTab({ values, update }: { values: Values; update: UpdateSearch }): ReactElement {
  const canInspect = useCan('quarantine:read');
  const sort = sortFromValues(values, ['downloadedAt', 'sizeBytes', 'lastScannedAt'], 'downloadedAt');
  const lifecycle = listValue(values.lifecycleStatus);
  const scan = listValue(values.scanStatus);
  const sha = values.sha256.trim().toLowerCase();
  const query = useDownloadArtifacts({
    lifecycleStatus: lifecycle,
    scanStatus: scan,
    source: values.source,
    cveId: cveFilterValue(values.cveId),
    sha256: SHA256.test(sha) ? sha : undefined,
    sort: sort.field,
    order: sort.order,
    ...pagingFromValues(values),
  });
  return (
    <div className="flex flex-col gap-4">
      <FilterBar>
        <MultiSelectFilter label="Lifecycle" values={lifecycle} options={optionsFrom(ARTIFACT_LIFECYCLE_STATUSES, humanize)}
          onChange={(lifecycleStatus) => { update({ lifecycleStatus }); }} />
        <MultiSelectFilter label="Scan" values={scan} options={optionsFrom(ARTIFACT_SCAN_STATUSES, humanize)}
          onChange={(scanStatus) => { update({ scanStatus }); }} />
        <SelectFilter id="artifact-source" label="Source" value={values.source} options={optionsFrom(DOWNLOAD_SOURCES, humanize)}
          onChange={(source) => { update({ source }); }} />
        <CveIdFilter value={values.cveId} update={update} />
        <SearchFilter id="artifact-sha" label="SHA-256" value={values.sha256} minLength={64} placeholder="Full hex digest"
          onChange={(sha256) => { update({ sha256 }); }} />
      </FilterBar>
      <p className="text-xs text-muted-foreground">
        Release, scan result and analyst verification are independent: a released artifact is not verified, and a clean scan is not a verdict.
        {canInspect === false ? ' Quarantined and rejected artifacts are hidden from your role.' : ''}
      </p>
      <ResultsPanel query={query} update={update}>
        <DataTable caption="Stored artifacts" columns={DOWNLOAD_ARTIFACT_COLUMNS} rows={query.data?.data} loading={query.isPending}
          fetching={query.isFetching} getRowKey={(row) => row.id} rowHref={(row) => `/downloads/artifacts/${row.id}`}
          sort={sort} onSortChange={(next) => { update({ sort: next.field, order: next.order }); }}
          emptyTitle="No stored artifacts" emptyDescription="No downloaded file matches these filters." />
      </ResultsPanel>
    </div>
  );
}

export function DownloadSourceCard({ source }: { source: DownloadSourceStatus }): ReactElement {
  return (
    <li className="flex flex-col gap-3 rounded-lg border border-border p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="font-medium">{source.name}</p>
          <p className="text-xs text-muted-foreground">{source.description}</p>
        </div>
        <div className="flex gap-1">
          <EnabledBadge enabled={source.enabled} />
          {source.automatic ? <Badge variant="info">Automatic downloads</Badge> : <Badge variant="outline">Manual only</Badge>}
        </div>
      </div>
      <dl className="grid gap-3 text-sm sm:grid-cols-3">
        <div>
          <dt className="text-xs text-muted-foreground">Allowed hosts</dt>
          <dd className="font-mono-id text-xs break-all">{source.allowedHosts.join(', ')}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Allowed file types</dt>
          <dd>{source.allowedFileTypes.map(humanize).join(', ')}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Size limit</dt>
          <dd className="tabular-nums">{formatBytes(source.maxBytes)}</dd>
        </div>
      </dl>
      {source.termsUrl === null ? null : <ExternalLink href={source.termsUrl} className="text-xs">Source terms of use</ExternalLink>}
    </li>
  );
}

function SourcesTab(): ReactElement {
  const query = useDownloadSources();
  return (
    <Section title="Approved download sources" description="Only these sources can be downloaded from. Each source builds its own canonical URLs and checks every redirect against its host allowlist.">
      <QueryState query={query} isEmpty={(data) => data.data.length === 0} empty={<EmptyState title="No download sources" description="The Download Service has no sources configured." />}>
        {(data) => <ul className="flex flex-col gap-3">{data.data.map((source) => <DownloadSourceCard key={source.source} source={source} />)}</ul>}
      </QueryState>
    </Section>
  );
}

const REQUEST_COUNTS: readonly QueryParams[] = [{ status: ['pending', 'downloading'] }, { status: ['failed', 'rejected'] }];
const ARTIFACT_COUNTS: readonly QueryParams[] = [
  { lifecycleStatus: ['quarantined'] },
  { lifecycleStatus: ['released'] },
  { scanStatus: ['malicious', 'suspicious', 'integrity-failure'] },
];

function DownloadStats(): ReactElement {
  const canInspect = useCan('quarantine:read');
  const requests = useApiCounts('download-requests', REQUEST_COUNTS);
  const artifacts = useApiCounts(
    'download-artifacts',
    ARTIFACT_COUNTS,
    canInspect !== undefined,
  );
  const [active, failed] = requests.counts;
  const [quarantined, released, flagged] = artifacts.counts;
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
      <StatCard label="Queued or running" value={active} loading={requests.isPending} error={requests.error !== null} icon={<Clock className="size-4" aria-hidden="true" />}
        href="/downloads?status=pending,downloading" />
      <StatCard label="Failed or rejected" value={failed} loading={requests.isPending} error={requests.error !== null} icon={<Ban className="size-4" aria-hidden="true" />}
        href="/downloads?status=failed,rejected" />
      {canInspect === false ? (
        <StatCard label="In quarantine" value={null} loading={false} hint="Requires quarantine access" icon={<Lock className="size-4" aria-hidden="true" />} />
      ) : (
        <StatCard label="In quarantine" value={quarantined} loading={artifacts.isPending} error={artifacts.error !== null} icon={<Lock className="size-4" aria-hidden="true" />}
          href="/downloads?tab=artifacts&lifecycleStatus=quarantined" />
      )}
      <StatCard label="Released" value={released} loading={artifacts.isPending} error={artifacts.error !== null} icon={<Unlock className="size-4" aria-hidden="true" />}
        href="/downloads?tab=artifacts&lifecycleStatus=released" />
      <StatCard label="Flagged by scanners" value={flagged} loading={artifacts.isPending} error={artifacts.error !== null} icon={<ShieldX className="size-4" aria-hidden="true" />}
        hint="Malicious, suspicious or integrity failure" href="/downloads?tab=artifacts&scanStatus=malicious,suspicious,integrity-failure" />
    </div>
  );
}

export function DownloadManagerView(): ReactElement {
  const { values, update } = useSearchState(DEFAULTS);
  const canSchedule = useCan('download:schedule');
  const tab = (TABS as readonly string[]).includes(values.tab) ? values.tab : 'requests';
  return (
    <>
      <PageHeader
        title="Download Manager"
        description="Controlled downloads of public PoC content. Files are fetched only from approved sources, hashed, stored in quarantine and scanned. Nothing is ever executed or extracted."
        actions={canSchedule === true ? <ScheduleDownloadForm /> : undefined}
      />
      <DownloadStats />
      <Tabs value={tab} onValueChange={(next) => { update({ tab: next, sort: '', order: '', status: '', lifecycleStatus: '', scanStatus: '' }); }}>
        <TabsList>
          <TabsTrigger value="requests">Requests</TabsTrigger>
          <TabsTrigger value="artifacts">Stored artifacts</TabsTrigger>
          <TabsTrigger value="sources"><CheckCircle2 className="size-3.5" aria-hidden="true" /> Sources</TabsTrigger>
        </TabsList>
        <TabsContent value="requests"><RequestsTab values={values} update={update} /></TabsContent>
        <TabsContent value="artifacts"><ArtifactsTab values={values} update={update} /></TabsContent>
        <TabsContent value="sources"><SourcesTab /></TabsContent>
      </Tabs>
    </>
  );
}
