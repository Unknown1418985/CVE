'use client';

import {
  ARTIFACT_VERIFICATION_STATUSES,
  POC_REPOSITORY_SORT_FIELDS,
  type PocArtifact,
  type PocAssociation,
  type PocRepository,
} from '@cve/contracts';
import { GitFork, Star } from 'lucide-react';
import type { ReactElement } from 'react';

import { DataTable, type Column, type SortOrder } from '@/components/data/data-table';
import { FilterBar, FilterField, MultiSelectFilter, SearchFilter, SelectFilter, optionsFrom } from '@/components/data/filters';
import { CveLink, InternalLink } from '@/components/data/links';
import { PageHeader } from '@/components/data/page-header';
import { Pagination } from '@/components/data/pagination';
import { ErrorState } from '@/components/data/states';
import { ConfidenceBadge, ReviewStatusBadge, VerificationBadge } from '@/components/data/status-badges';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { intValue, listValue, useSearchState } from '@/hooks/use-search-state';
import { formatBytes, formatDate, formatNumber, humanize, shortHash } from '@/lib/format';

import { usePocArtifacts, usePocAssociations, usePocRepositories } from './api';
import { ReviewActions } from './review-actions';

const DEFAULTS = {
  tab: 'repositories',
  q: '',
  cveId: '',
  owner: '',
  status: '',
  minConfidence: '',
  isFork: '',
  verificationStatus: '',
  duplicate: '',
  confidenceLevel: '',
  sort: '',
  order: 'desc',
  page: '1',
  pageSize: '25',
} as const;

type Values = Record<keyof typeof DEFAULTS, string>;
type Update = (patch: Record<string, string | number | string[]>) => void;

const CVE_PATTERN = /^CVE-\d{4}-\d{4,19}$/;

export const REPOSITORY_COLUMNS: readonly Column<PocRepository>[] = [
  {
    id: 'name',
    header: 'Repository',
    cell: (row) => (
      <div className="flex flex-col gap-0.5">
        <InternalLink href={`/pocs/${row.id}`} className="font-medium">{row.fullName}</InternalLink>
        <span className="line-clamp-1 max-w-md text-xs text-muted-foreground">{row.description ?? 'No description'}</span>
      </div>
    ),
  },
  {
    id: 'cves',
    header: 'CVEs',
    cell: (row) => (
      <div className="flex flex-wrap gap-1">
        {row.cveIds.slice(0, 3).map((cveId) => <CveLink key={cveId} cveId={cveId} className="text-xs" />)}
        {row.cveIds.length > 3 ? <span className="text-xs text-muted-foreground">+{row.cveIds.length - 3}</span> : null}
      </div>
    ),
  },
  { id: 'confidence', header: 'Max confidence', sortField: 'maxConfidence', cell: (row) => <ConfidenceBadge level={row.maxConfidence === null ? null : row.maxConfidence >= 0.7 ? 'high' : row.maxConfidence >= 0.4 ? 'medium' : 'low'} value={row.maxConfidence} /> },
  {
    id: 'stars',
    header: 'Stars',
    sortField: 'stars',
    className: 'text-right',
    cell: (row) => (
      <span className="inline-flex items-center gap-1 tabular-nums"><Star className="size-3" aria-hidden="true" />{formatNumber(row.stars)}</span>
    ),
  },
  {
    id: 'flags',
    header: 'Flags',
    cell: (row) => (
      <div className="flex flex-wrap gap-1">
        {row.isFork ? <Badge variant="outline" className="gap-1"><GitFork className="size-3" aria-hidden="true" />Fork</Badge> : null}
        {row.isArchived ? <Badge variant="outline">Archived</Badge> : null}
        {row.status === 'unavailable' ? <Badge variant="warning">Unavailable</Badge> : null}
        {row.language === null ? null : <Badge variant="muted">{row.language}</Badge>}
      </div>
    ),
  },
  { id: 'pushed', header: 'Last push', sortField: 'sourcePushedAt', cell: (row) => formatDate(row.sourcePushedAt) },
  { id: 'discovered', header: 'Discovered', sortField: 'firstDiscoveredAt', cell: (row) => formatDate(row.firstDiscoveredAt) },
];

export const ARTIFACT_COLUMNS: readonly Column<PocArtifact>[] = [
  {
    id: 'artifact',
    header: 'Snapshot',
    cell: (row) => (
      <div className="flex flex-col gap-0.5">
        <InternalLink href={`/pocs/artifacts/${row.id}`}>{row.repositoryFullName}</InternalLink>
        <span className="font-mono-id text-xs text-muted-foreground">@{shortHash(row.commitSha, 10)}</span>
      </div>
    ),
  },
  { id: 'files', header: 'Files', className: 'text-right', cell: (row) => <span className="tabular-nums">{formatNumber(row.fileCount)} · {formatBytes(row.totalBytes)}</span> },
  {
    id: 'risk',
    header: 'Risk indicators',
    cell: (row) =>
      row.riskIndicators.length === 0 ? (
        <span className="text-muted-foreground">None</span>
      ) : (
        <div className="flex flex-wrap gap-1">
          {row.riskIndicators.map((indicator) => (
            <Badge key={indicator} variant={indicator === 'duplicate-of-malicious' ? 'destructive' : 'warning'}>{humanize(indicator)}</Badge>
          ))}
        </div>
      ),
  },
  {
    id: 'duplicate',
    header: 'Duplicate',
    cell: (row) => (row.duplicate === null ? '—' : <span className="text-xs">{humanize(row.duplicate.kind)} of {row.duplicate.ofRepositoryFullName}</span>),
  },
  { id: 'verification', header: 'Verification', cell: (row) => <VerificationBadge status={row.verificationStatus} /> },
  { id: 'discovered', header: 'Discovered', sortField: 'discoveredAt', cell: (row) => formatDate(row.discoveredAt) },
];

export const ASSOCIATION_COLUMNS: readonly Column<PocAssociation>[] = [
  { id: 'cve', header: 'CVE', cell: (row) => <CveLink cveId={row.cveId} /> },
  { id: 'repository', header: 'Repository', cell: (row) => <InternalLink href={`/pocs/${row.repositoryId}`}>{row.repositoryFullName}</InternalLink> },
  { id: 'confidence', header: 'Confidence', sortField: 'confidence', cell: (row) => <ConfidenceBadge level={row.confidenceLevel} value={row.confidence} /> },
  {
    id: 'signals',
    header: 'Signals',
    className: 'max-w-sm',
    cell: (row) => (
      <div className="flex flex-wrap gap-1">
        {row.signals.map((signal) => <Badge key={signal.kind} variant="outline" title={signal.evidence ?? undefined}>{humanize(signal.kind)}</Badge>)}
        {row.penalties.map((penalty) => <Badge key={penalty.kind} variant="warning" title={penalty.detail ?? undefined}>−{humanize(penalty.kind)}</Badge>)}
      </div>
    ),
  },
  { id: 'review', header: 'Review', cell: (row) => <ReviewStatusBadge status={row.reviewStatus} /> },
  { id: 'actions', header: <span className="sr-only">Actions</span>, cell: (row) => <ReviewActions association={row} /> },
];

function sortOf(values: Values, allowed: readonly string[], fallback: string): { field: string; order: SortOrder } {
  return { field: allowed.includes(values.sort) ? values.sort : fallback, order: values.order === 'asc' ? 'asc' : 'desc' };
}

function RepositoriesTab({ values, update }: { values: Values; update: Update }): ReactElement {
  const sort = sortOf(values, POC_REPOSITORY_SORT_FIELDS, 'firstDiscoveredAt');
  const query = usePocRepositories({
    q: values.q,
    cveId: CVE_PATTERN.test(values.cveId) ? values.cveId : undefined,
    owner: values.owner,
    status: values.status,
    minConfidence: values.minConfidence,
    isFork: values.isFork,
    sort: sort.field,
    order: sort.order,
    page: intValue(values.page, 1),
    pageSize: intValue(values.pageSize, 25),
  });
  return (
    <div className="flex flex-col gap-4">
      <FilterBar>
        <SearchFilter id="poc-q" label="Repository" value={values.q} placeholder="owner/name" onChange={(q) => { update({ q }); }} />
        <CveFilter value={values.cveId} update={update} />
        <FilterField label="Owner" htmlFor="poc-owner" className="w-40">
          <Input id="poc-owner" value={values.owner} maxLength={64} onChange={(event) => { update({ owner: event.target.value }); }} />
        </FilterField>
        <SelectFilter id="poc-confidence" label="Min confidence" value={values.minConfidence}
          options={[{ value: '0.4', label: '40%' }, { value: '0.7', label: '70%' }, { value: '0.9', label: '90%' }]}
          onChange={(minConfidence) => { update({ minConfidence }); }} />
        <SelectFilter id="poc-status" label="Status" value={values.status}
          options={[{ value: 'active', label: 'Active' }, { value: 'unavailable', label: 'Unavailable' }]}
          onChange={(status) => { update({ status }); }} />
        <SelectFilter id="poc-fork" label="Forks" value={values.isFork}
          options={[{ value: 'false', label: 'Exclude forks' }, { value: 'true', label: 'Only forks' }]}
          onChange={(isFork) => { update({ isFork }); }} />
      </FilterBar>
      <Results query={query} update={update}>
        <DataTable caption="PoC repositories" columns={REPOSITORY_COLUMNS} rows={query.data?.data} loading={query.isPending}
          fetching={query.isFetching} getRowKey={(row) => row.id} rowHref={(row) => `/pocs/${row.id}`}
          sort={sort} onSortChange={(next) => { update({ sort: next.field, order: next.order }); }}
          emptyTitle="No PoC repositories" emptyDescription="Discovery has not found repositories matching these filters." />
      </Results>
    </div>
  );
}

function ArtifactsTab({ values, update }: { values: Values; update: Update }): ReactElement {
  const sort = sortOf(values, ['discoveredAt', 'verificationUpdatedAt'], 'discoveredAt');
  const statuses = listValue(values.verificationStatus);
  const query = usePocArtifacts({
    cveId: CVE_PATTERN.test(values.cveId) ? values.cveId : undefined,
    verificationStatus: statuses,
    duplicate: values.duplicate,
    sort: sort.field,
    order: sort.order,
    page: intValue(values.page, 1),
    pageSize: intValue(values.pageSize, 25),
  });
  return (
    <div className="flex flex-col gap-4">
      <FilterBar>
        <CveFilter value={values.cveId} update={update} />
        <MultiSelectFilter label="Verification" values={statuses} options={optionsFrom(ARTIFACT_VERIFICATION_STATUSES, humanize)}
          onChange={(verificationStatus) => { update({ verificationStatus }); }} />
        <SelectFilter id="artifact-duplicate" label="Duplicates" value={values.duplicate}
          options={[{ value: 'false', label: 'Originals only' }, { value: 'true', label: 'Duplicates only' }]}
          onChange={(duplicate) => { update({ duplicate }); }} />
      </FilterBar>
      <p className="text-xs text-muted-foreground">
        Artifacts are repository snapshots described by their file listing only. Malicious artifacts are hidden unless your role may inspect quarantined content.
      </p>
      <Results query={query} update={update}>
        <DataTable caption="PoC artifacts" columns={ARTIFACT_COLUMNS} rows={query.data?.data} loading={query.isPending}
          fetching={query.isFetching} getRowKey={(row) => row.id} rowHref={(row) => `/pocs/artifacts/${row.id}`}
          sort={sort} onSortChange={(next) => { update({ sort: next.field, order: next.order }); }}
          emptyTitle="No artifacts" />
      </Results>
    </div>
  );
}

function ReviewTab({ values, update }: { values: Values; update: Update }): ReactElement {
  const sort = sortOf(values, ['confidence', 'firstDiscoveredAt', 'lastEvaluatedAt'], 'confidence');
  const levels = listValue(values.confidenceLevel);
  const query = usePocAssociations({
    reviewStatus: ['candidate'],
    cveId: CVE_PATTERN.test(values.cveId) ? values.cveId : undefined,
    confidenceLevel: levels,
    sort: sort.field,
    order: sort.order,
    page: intValue(values.page, 1),
    pageSize: intValue(values.pageSize, 25),
  });
  return (
    <div className="flex flex-col gap-4">
      <FilterBar>
        <CveFilter value={values.cveId} update={update} />
        <MultiSelectFilter label="Confidence" values={levels} options={optionsFrom(['high', 'medium', 'low'], humanize)}
          onChange={(confidenceLevel) => { update({ confidenceLevel }); }} />
      </FilterBar>
      <Results query={query} update={update}>
        <DataTable caption="Associations awaiting review" columns={ASSOCIATION_COLUMNS} rows={query.data?.data} loading={query.isPending}
          fetching={query.isFetching} getRowKey={(row) => row.id}
          sort={sort} onSortChange={(next) => { update({ sort: next.field, order: next.order }); }}
          emptyTitle="Nothing to review" emptyDescription="Every discovered association has been reviewed." />
      </Results>
    </div>
  );
}

function CveFilter({ value, update }: { value: string; update: Update }): ReactElement {
  const invalid = value !== '' && !CVE_PATTERN.test(value);
  return (
    <FilterField label="CVE ID" htmlFor="filter-cve" className="w-44">
      <Input id="filter-cve" value={value} placeholder="CVE-2026-1234" maxLength={30} aria-invalid={invalid}
        onChange={(event) => { update({ cveId: event.target.value.trim().toUpperCase() }); }} />
    </FilterField>
  );
}

interface PagedQuery {
  readonly data: { meta: import('@cve/contracts').PaginationMeta } | undefined;
  readonly isError: boolean;
  readonly error: unknown;
  refetch: () => unknown;
}

function Results({ query, update, children }: { query: PagedQuery; update: Update; children: ReactElement }): ReactElement {
  return (
    <section className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4">
      {query.isError ? <ErrorState error={query.error} onRetry={() => { void query.refetch(); }} /> : children}
      {query.data === undefined || query.isError ? null : (
        <Pagination meta={query.data.meta} onPageChange={(page) => { update({ page }); }} onPageSizeChange={(pageSize) => { update({ pageSize }); }} />
      )}
    </section>
  );
}

export function PocRepositoryView(): ReactElement {
  const { values, update } = useSearchState(DEFAULTS);
  const tab = ['repositories', 'artifacts', 'review'].includes(values.tab) ? values.tab : 'repositories';
  return (
    <>
      <PageHeader
        title="PoC Repository"
        description="Public proof-of-concept repositories discovered by the PoC Service, their CVE associations and repository snapshots. Only metadata is stored here; content is downloaded into quarantine by the Download Manager."
      />
      <Tabs value={tab} onValueChange={(next) => { update({ tab: next, sort: '', order: '' }); }}>
        <TabsList>
          <TabsTrigger value="repositories">Repositories</TabsTrigger>
          <TabsTrigger value="artifacts">Artifacts</TabsTrigger>
          <TabsTrigger value="review">Review queue</TabsTrigger>
        </TabsList>
        <TabsContent value="repositories"><RepositoriesTab values={values} update={update} /></TabsContent>
        <TabsContent value="artifacts"><ArtifactsTab values={values} update={update} /></TabsContent>
        <TabsContent value="review"><ReviewTab values={values} update={update} /></TabsContent>
      </Tabs>
    </>
  );
}
