'use client';

import {
  CATALOG_SYNC_STATUSES,
  DISCOVERY_RUN_STATUSES,
  EXPLOIT_CATALOG_CONNECTORS,
  INTELLIGENCE_SOURCES,
  POC_CONNECTORS,
  SYNC_RUN_STATUSES,
  SYNC_TRIGGERS,
  type CatalogSyncRun,
  type DiscoveryRun,
  type ExploitConnectorStatus,
  type PocConnectorStatus,
  type SourceStatus,
  type SyncRun,
} from '@cve/contracts';
import { KeyRound, Play, RotateCcw } from 'lucide-react';
import { useState, type ReactElement } from 'react';

import { ConfirmDialog } from '@/components/data/confirm-dialog';
import { DataTable, type Column } from '@/components/data/data-table';
import { FilterBar, SelectFilter, optionsFrom } from '@/components/data/filters';
import { CveLink, ExternalLink, InternalLink } from '@/components/data/links';
import { PageHeader, Section } from '@/components/data/page-header';
import { ResultsPanel, pagingFromValues, type UpdateSearch } from '@/components/data/results';
import { EmptyState, QueryState } from '@/components/data/states';
import { EnabledBadge, RunStatusBadge } from '@/components/data/status-badges';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useCan } from '@/features/auth/use-me';
import { DownloadSourceCard } from '@/features/downloads/download-manager';
import { useDownloadSources } from '@/features/downloads/api';
import { useExploitSources, useExploitSyncRuns } from '@/features/exploits/api';
import { usePocConnectors, useDiscoveryRuns } from '@/features/pocs/api';
import { useTriggerDiscovery } from '@/features/pocs/mutations';
import { useSearchState } from '@/hooks/use-search-state';
import {
  formatDateTime,
  formatDuration,
  formatNumber,
  formatRelative,
  humanize,
} from '@/lib/format';

import { useSources, useSyncRun, useSyncRuns } from './api';
import { useRetrySyncRun, useTriggerCatalogSync, useTriggerSourceSync } from './mutations';

const DEFAULTS = {
  tab: 'intelligence',
  source: '',
  status: '',
  trigger: '',
  connector: '',
  page: '1',
  pageSize: '25',
} as const;
type Values = Record<keyof typeof DEFAULTS, string>;

function duration(startedAt: string, finishedAt: string | null): string {
  if (finishedAt === null) return 'Running';
  return formatDuration(Date.parse(finishedAt) - Date.parse(startedAt));
}

function TermsLine({
  license,
  termsUrl,
  attribution,
}: {
  license?: string;
  termsUrl: string | null;
  attribution?: string;
}): ReactElement {
  return (
    <p className="text-xs text-muted-foreground">
      {license === undefined ? null : <>License: {license}. </>}
      {attribution === undefined ? null : <>{attribution} </>}
      {termsUrl === null ? null : <ExternalLink href={termsUrl}>Terms of use</ExternalLink>}
    </p>
  );
}

// ------------------------------------------------------------------------------------ intelligence

function SourceCard({ source }: { source: SourceStatus }): ReactElement {
  const canManage = useCan('data-source:manage');
  const trigger = useTriggerSourceSync();
  const { state } = source;
  return (
    <li
      className="flex flex-col gap-3 rounded-lg border border-border p-4"
      data-testid={`source-${source.source}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="font-medium">{source.name}</p>
          <p className="text-xs text-muted-foreground">{source.description}</p>
        </div>
        <div className="flex flex-wrap items-center gap-1">
          <EnabledBadge enabled={source.enabled} />
          {state.running ? (
            <Badge variant="info">Running</Badge>
          ) : (
            <RunStatusBadge status={state.lastRunStatus} />
          )}
        </div>
      </div>
      <dl className="grid gap-3 text-sm sm:grid-cols-4">
        <div>
          <dt className="text-xs text-muted-foreground">Last run</dt>
          <dd title={formatDateTime(state.lastRunAt)}>{formatRelative(state.lastRunAt)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Last success</dt>
          <dd title={formatDateTime(state.lastSuccessAt)}>{formatRelative(state.lastSuccessAt)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Consecutive failures</dt>
          <dd
            className={
              state.consecutiveFailures > 0 ? 'text-status-down tabular-nums' : 'tabular-nums'
            }
          >
            {state.consecutiveFailures}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Schedule</dt>
          <dd className="font-mono-id text-xs">{source.schedule ?? 'Manual only'}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Credentials</dt>
          <dd className="inline-flex items-center gap-1">
            <KeyRound className="size-3.5 text-muted-foreground" aria-hidden="true" />
            {source.authentication.mode === 'none'
              ? 'Not needed'
              : source.authentication.configured
                ? 'Configured'
                : source.authentication.mode === 'required'
                  ? 'Missing (required)'
                  : 'Not configured (optional)'}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Rate limit</dt>
          <dd className="tabular-nums">
            {source.rateLimit.maxRequests} requests / {formatDuration(source.rateLimit.windowMs)}
          </dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-xs text-muted-foreground">Endpoint</dt>
          <dd className="font-mono-id text-xs break-all">{source.baseUrl}</dd>
        </div>
      </dl>
      <TermsLine
        license={source.license}
        termsUrl={source.termsUrl}
        attribution={source.attribution}
      />
      {canManage === true && source.enabled ? (
        <div className="flex flex-wrap gap-2">
          <ConfirmDialog
            trigger={
              <Button size="sm">
                <Play aria-hidden="true" /> Sync now
              </Button>
            }
            title={`Synchronise ${source.name}`}
            description="Queues an incremental synchronisation. A recent failed run is resumed from its checkpoint. The source's rate limit and terms apply."
            confirmLabel="Queue sync"
            onConfirm={() => trigger.mutateAsync({ source: source.source, fresh: false })}
          />
          <ConfirmDialog
            trigger={
              <Button size="sm" variant="outline">
                Fresh sync
              </Button>
            }
            title={`Fresh synchronisation of ${source.name}`}
            description="Starts from the stored cursor and ignores the checkpoint of any failed run. Use this when a checkpoint is suspected to be wrong."
            confirmLabel="Queue fresh sync"
            onConfirm={() => trigger.mutateAsync({ source: source.source, fresh: true })}
          />
        </div>
      ) : null}
    </li>
  );
}

function SyncRunDialog({
  runId,
  onClose,
}: {
  runId: string | null;
  onClose: () => void;
}): ReactElement {
  const query = useSyncRun(runId);
  return (
    <Dialog
      open={runId !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Synchronisation run</DialogTitle>
          <DialogDescription>
            Counters and validation issues reported by the run (at most the first 200 issues).
          </DialogDescription>
        </DialogHeader>
        <QueryState query={query}>
          {(data) => {
            const run = data.data;
            return (
              <div className="flex max-h-[60vh] flex-col gap-4 overflow-y-auto">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-medium">{humanize(run.source)}</span>
                  <RunStatusBadge status={run.status} />
                  <span className="text-muted-foreground">
                    {formatDateTime(run.startedAt)} · {duration(run.startedAt, run.finishedAt)}
                  </span>
                </div>
                {run.error === null ? null : (
                  <p className="text-sm text-status-down">{run.error}</p>
                )}
                <dl className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
                  {Object.entries(run.stats).map(([key, value]) => (
                    <div key={key} className="rounded border border-border p-2">
                      <dt className="text-xs text-muted-foreground">{humanize(key)}</dt>
                      <dd className="tabular-nums">{formatNumber(value)}</dd>
                    </div>
                  ))}
                </dl>
                {run.issues.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No validation issues.</p>
                ) : (
                  <ul className="flex flex-col divide-y divide-border text-sm">
                    {run.issues.map((issue, index) => (
                      <li key={`${issue.createdAt}-${String(index)}`} className="py-2">
                        {issue.sourceRecordId === null ? null : (
                          <span className="font-mono-id text-xs">{issue.sourceRecordId}: </span>
                        )}
                        {issue.message}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            );
          }}
        </QueryState>
      </DialogContent>
    </Dialog>
  );
}

function RetryRun({ run }: { run: SyncRun }): ReactElement | null {
  const canManage = useCan('data-source:manage');
  const retry = useRetrySyncRun();
  if (canManage !== true || (run.status !== 'failed' && run.status !== 'abandoned')) return null;
  return (
    <ConfirmDialog
      trigger={
        <Button size="sm" variant="outline">
          <RotateCcw aria-hidden="true" /> Retry
        </Button>
      }
      title="Retry this run"
      description="Queues a new run that resumes from this run's checkpoint."
      confirmLabel="Retry run"
      onConfirm={() => retry.mutateAsync({ runId: run.id })}
    />
  );
}

function IntelligenceTab({
  values,
  update,
}: {
  values: Values;
  update: UpdateSearch;
}): ReactElement {
  const sources = useSources();
  const runs = useSyncRuns({
    source: values.source,
    status: values.status,
    trigger: values.trigger,
    ...pagingFromValues(values),
  });
  const [openRun, setOpenRun] = useState<string | null>(null);
  const columns: readonly Column<SyncRun>[] = [
    {
      id: 'source',
      header: 'Source',
      cell: (row) => (
        <Button
          variant="link"
          className="h-auto p-0"
          onClick={() => {
            setOpenRun(row.id);
          }}
        >
          {humanize(row.source)}
        </Button>
      ),
    },
    { id: 'status', header: 'Status', cell: (row) => <RunStatusBadge status={row.status} /> },
    {
      id: 'trigger',
      header: 'Trigger',
      cell: (row) =>
        `${humanize(row.trigger)}${row.requestedBy === null ? '' : ` · ${row.requestedBy}`}`,
    },
    { id: 'started', header: 'Started', cell: (row) => formatDateTime(row.startedAt) },
    { id: 'duration', header: 'Duration', cell: (row) => duration(row.startedAt, row.finishedAt) },
    {
      id: 'stats',
      header: 'Fetched / created / updated',
      className: 'text-right',
      cell: (row) => (
        <span className="tabular-nums">
          {formatNumber(row.stats.fetched)} / {formatNumber(row.stats.created)} /{' '}
          {formatNumber(row.stats.updated)}
        </span>
      ),
    },
    {
      id: 'issues',
      header: 'Issues',
      className: 'text-right',
      cell: (row) => (
        <span className={row.issueCount > 0 ? 'text-status-degraded tabular-nums' : 'tabular-nums'}>
          {formatNumber(row.issueCount)}
        </span>
      ),
    },
    {
      id: 'actions',
      header: <span className="sr-only">Actions</span>,
      cell: (row) => <RetryRun run={row} />,
    },
  ];
  return (
    <div className="flex flex-col gap-4">
      <Section
        title="Intelligence sources"
        description="CVE, KEV, EPSS and advisory feeds collected by the Intelligence Service."
      >
        <QueryState
          query={sources}
          isEmpty={(data) => data.data.length === 0}
          empty={<EmptyState title="No sources configured" />}
        >
          {(data) => (
            <ul className="grid gap-3 xl:grid-cols-2">
              {data.data.map((source) => (
                <SourceCard key={source.source} source={source} />
              ))}
            </ul>
          )}
        </QueryState>
      </Section>
      <div className="flex flex-col gap-3">
        <h2 className="text-base font-semibold">Synchronisation history</h2>
        <FilterBar>
          <SelectFilter
            id="run-source"
            label="Source"
            value={values.source}
            options={optionsFrom(INTELLIGENCE_SOURCES, humanize)}
            onChange={(source) => {
              update({ source });
            }}
          />
          <SelectFilter
            id="run-status"
            label="Status"
            value={values.status}
            options={optionsFrom(SYNC_RUN_STATUSES, humanize)}
            onChange={(status) => {
              update({ status });
            }}
          />
          <SelectFilter
            id="run-trigger"
            label="Trigger"
            value={values.trigger}
            options={optionsFrom(SYNC_TRIGGERS, humanize)}
            onChange={(trigger) => {
              update({ trigger });
            }}
          />
        </FilterBar>
        <ResultsPanel query={runs} update={update}>
          <DataTable
            caption="Synchronisation runs"
            columns={columns}
            rows={runs.data?.data}
            loading={runs.isPending}
            fetching={runs.isFetching}
            getRowKey={(row) => row.id}
            emptyTitle="No synchronisation runs"
            emptyDescription="No run matches these filters. Runs appear here once a sync is scheduled or triggered."
          />
        </ResultsPanel>
      </div>
      <SyncRunDialog
        runId={openRun}
        onClose={() => {
          setOpenRun(null);
        }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------------- PoC discovery

function ConnectorCard({ connector }: { connector: PocConnectorStatus }): ReactElement {
  return (
    <li className="flex flex-col gap-2 rounded-lg border border-border p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="font-medium">{connector.name}</p>
          <p className="text-xs text-muted-foreground">{connector.description}</p>
        </div>
        <div className="flex flex-wrap gap-1">
          <EnabledBadge enabled={connector.enabled} />
          {connector.approved ? (
            <Badge variant="success">Approved</Badge>
          ) : (
            <Badge variant="warning">Not approved</Badge>
          )}
          <RunStatusBadge status={connector.lastRunStatus} />
        </div>
      </div>
      <dl className="grid gap-3 text-sm sm:grid-cols-3">
        <div>
          <dt className="text-xs text-muted-foreground">Last run</dt>
          <dd>{formatRelative(connector.lastRunAt)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Schedule</dt>
          <dd className="font-mono-id text-xs">{connector.schedule ?? 'Manual or event-driven'}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Credentials</dt>
          <dd>
            {connector.authentication.mode === 'none'
              ? 'Not needed'
              : connector.authentication.configured
                ? 'Configured'
                : 'Not configured (lower rate limit)'}
          </dd>
        </div>
        <div className="sm:col-span-3">
          <dt className="text-xs text-muted-foreground">Allowed origins</dt>
          <dd className="font-mono-id text-xs break-all">{connector.allowedOrigins.join(', ')}</dd>
        </div>
      </dl>
      <TermsLine termsUrl={connector.termsUrl} />
    </li>
  );
}

const DISCOVERY_COLUMNS: readonly Column<DiscoveryRun>[] = [
  { id: 'connector', header: 'Connector', cell: (row) => humanize(row.connector) },
  {
    id: 'mode',
    header: 'Scope',
    cell: (row) =>
      row.mode === 'cve' && row.cveId !== null ? (
        <span>
          CVE search · <CveLink cveId={row.cveId} />
        </span>
      ) : row.mode === 'repository' && row.repositoryId !== null ? (
        <InternalLink href={`/pocs/${row.repositoryId}`}>Repository inspection</InternalLink>
      ) : (
        humanize(row.mode)
      ),
  },
  {
    id: 'status',
    header: 'Status',
    cell: (row) => (
      <div className="flex flex-col gap-1">
        <RunStatusBadge status={row.status} />
        {row.error === null ? null : (
          <span className="max-w-xs text-xs text-status-down line-clamp-2">{row.error}</span>
        )}
      </div>
    ),
  },
  {
    id: 'trigger',
    header: 'Trigger',
    cell: (row) =>
      `${humanize(row.trigger)}${row.requestedBy === null ? '' : ` · ${row.requestedBy}`}`,
  },
  { id: 'started', header: 'Started', cell: (row) => formatDateTime(row.startedAt) },
  { id: 'duration', header: 'Duration', cell: (row) => duration(row.startedAt, row.finishedAt) },
  {
    id: 'stats',
    header: 'Candidates / new repos / new links',
    className: 'text-right',
    cell: (row) => (
      <span className="tabular-nums">
        {formatNumber(row.stats.candidates)} / {formatNumber(row.stats.repositoriesCreated)} /{' '}
        {formatNumber(row.stats.associationsCreated)}
      </span>
    ),
  },
];

function PocDiscoveryTab({
  values,
  update,
}: {
  values: Values;
  update: UpdateSearch;
}): ReactElement {
  const canManage = useCan('poc:manage');
  const connectors = usePocConnectors();
  const runs = useDiscoveryRuns({
    connector: values.connector,
    status: values.status,
    ...pagingFromValues(values),
  });
  const trigger = useTriggerDiscovery();
  return (
    <div className="flex flex-col gap-4">
      <Section
        title="Discovery connectors"
        description="Approved connectors the PoC Service uses to find public proof-of-concept repositories. Only metadata is collected."
        actions={
          canManage === true ? (
            <ConfirmDialog
              trigger={
                <Button size="sm">
                  <Play aria-hidden="true" /> Sweep recent
                </Button>
              }
              title="Discover recent PoC repositories"
              description="Queues a GitHub search for recently pushed repositories that mention CVE identifiers. Nothing is downloaded."
              confirmLabel="Queue discovery"
              onConfirm={() => trigger.mutateAsync({ mode: 'recent' })}
            />
          ) : undefined
        }
      >
        <QueryState
          query={connectors}
          isEmpty={(data) => data.data.length === 0}
          empty={<EmptyState title="No connectors configured" />}
        >
          {(data) => (
            <ul className="grid gap-3 xl:grid-cols-2">
              {data.data.map((connector) => (
                <ConnectorCard key={connector.connector} connector={connector} />
              ))}
            </ul>
          )}
        </QueryState>
      </Section>
      <FilterBar>
        <SelectFilter
          id="discovery-connector"
          label="Connector"
          value={values.connector}
          options={optionsFrom(POC_CONNECTORS, humanize)}
          onChange={(connector) => {
            update({ connector });
          }}
        />
        <SelectFilter
          id="discovery-status"
          label="Status"
          value={values.status}
          options={optionsFrom(DISCOVERY_RUN_STATUSES, humanize)}
          onChange={(status) => {
            update({ status });
          }}
        />
      </FilterBar>
      <ResultsPanel query={runs} update={update}>
        <DataTable
          caption="Discovery runs"
          columns={DISCOVERY_COLUMNS}
          rows={runs.data?.data}
          loading={runs.isPending}
          fetching={runs.isFetching}
          getRowKey={(row) => row.id}
          emptyTitle="No discovery runs"
        />
      </ResultsPanel>
    </div>
  );
}

// -------------------------------------------------------------------------------- exploit catalogs

function CatalogCard({ source }: { source: ExploitConnectorStatus }): ReactElement {
  const canManage = useCan('data-source:manage');
  const trigger = useTriggerCatalogSync();
  return (
    <li className="flex flex-col gap-2 rounded-lg border border-border p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="font-medium">{source.name}</p>
          <p className="text-xs text-muted-foreground">{source.description}</p>
        </div>
        <div className="flex flex-wrap gap-1">
          <EnabledBadge enabled={source.enabled} />
          <RunStatusBadge status={source.lastRunStatus} />
        </div>
      </div>
      <dl className="grid gap-3 text-sm sm:grid-cols-3">
        <div>
          <dt className="text-xs text-muted-foreground">Last run</dt>
          <dd>{formatRelative(source.lastRunAt)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Last success</dt>
          <dd>{formatRelative(source.lastSuccessAt)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Schedule</dt>
          <dd className="font-mono-id text-xs">{source.schedule ?? 'Manual only'}</dd>
        </div>
        <div className="sm:col-span-3">
          <dt className="text-xs text-muted-foreground">Catalog</dt>
          <dd className="font-mono-id text-xs break-all">{source.url}</dd>
        </div>
      </dl>
      <TermsLine termsUrl={source.termsUrl} attribution={source.attribution} />
      {canManage === true && source.enabled ? (
        <div>
          <ConfirmDialog
            trigger={
              <Button size="sm">
                <Play aria-hidden="true" /> Sync now
              </Button>
            }
            title={`Synchronise ${source.name}`}
            description="Queues a catalog synchronisation. Only metadata is imported; exploit code is never downloaded or run by this sync."
            confirmLabel="Queue sync"
            onConfirm={() => trigger.mutateAsync({ connector: source.connector })}
          />
        </div>
      ) : null}
    </li>
  );
}

const CATALOG_COLUMNS: readonly Column<CatalogSyncRun>[] = [
  { id: 'connector', header: 'Catalog', cell: (row) => humanize(row.connector) },
  {
    id: 'status',
    header: 'Status',
    cell: (row) => (
      <div className="flex flex-col gap-1">
        <div className="flex gap-1">
          <RunStatusBadge status={row.status} />
          {row.notModified ? <Badge variant="muted">Not modified</Badge> : null}
        </div>
        {row.error === null ? null : (
          <span className="max-w-xs text-xs text-status-down line-clamp-2">{row.error}</span>
        )}
      </div>
    ),
  },
  {
    id: 'trigger',
    header: 'Trigger',
    cell: (row) =>
      `${humanize(row.trigger)}${row.requestedBy === null ? '' : ` · ${row.requestedBy}`}`,
  },
  { id: 'started', header: 'Started', cell: (row) => formatDateTime(row.startedAt) },
  { id: 'duration', header: 'Duration', cell: (row) => duration(row.startedAt, row.finishedAt) },
  {
    id: 'stats',
    header: 'Fetched / created / updated',
    className: 'text-right',
    cell: (row) => (
      <span className="tabular-nums">
        {formatNumber(row.stats.fetched)} / {formatNumber(row.stats.created)} /{' '}
        {formatNumber(row.stats.updated)}
      </span>
    ),
  },
  {
    id: 'issues',
    header: 'Issues',
    className: 'text-right',
    cell: (row) => (
      <span
        className="tabular-nums"
        title={row.issues
          .slice(0, 5)
          .map((issue) => issue.message)
          .join('\n')}
      >
        {formatNumber(row.issues.length)}
      </span>
    ),
  },
];

function ExploitCatalogsTab({
  values,
  update,
}: {
  values: Values;
  update: UpdateSearch;
}): ReactElement {
  const sources = useExploitSources();
  const runs = useExploitSyncRuns({
    connector: values.connector,
    status: values.status,
    ...pagingFromValues(values),
  });
  return (
    <div className="flex flex-col gap-4">
      <Section
        title="Exploit catalogs"
        description="Public exploit catalogs synchronised by the Exploit Service."
      >
        <QueryState
          query={sources}
          isEmpty={(data) => data.data.length === 0}
          empty={<EmptyState title="No catalogs configured" />}
        >
          {(data) => (
            <ul className="grid gap-3 xl:grid-cols-2">
              {data.data.map((source) => (
                <CatalogCard key={source.connector} source={source} />
              ))}
            </ul>
          )}
        </QueryState>
      </Section>
      <FilterBar>
        <SelectFilter
          id="catalog-connector"
          label="Catalog"
          value={values.connector}
          options={optionsFrom(EXPLOIT_CATALOG_CONNECTORS, humanize)}
          onChange={(connector) => {
            update({ connector });
          }}
        />
        <SelectFilter
          id="catalog-status"
          label="Status"
          value={values.status}
          options={optionsFrom(CATALOG_SYNC_STATUSES, humanize)}
          onChange={(status) => {
            update({ status });
          }}
        />
      </FilterBar>
      <ResultsPanel query={runs} update={update}>
        <DataTable
          caption="Catalog synchronisation runs"
          columns={CATALOG_COLUMNS}
          rows={runs.data?.data}
          loading={runs.isPending}
          fetching={runs.isFetching}
          getRowKey={(row) => row.id}
          emptyTitle="No catalog runs"
        />
      </ResultsPanel>
    </div>
  );
}

function DownloadSourcesTab(): ReactElement {
  const query = useDownloadSources();
  return (
    <Section
      title="Download sources"
      description="Approved sources for controlled PoC downloads, with their host allowlists and limits."
    >
      <QueryState
        query={query}
        isEmpty={(data) => data.data.length === 0}
        empty={<EmptyState title="No download sources" />}
      >
        {(data) => (
          <ul className="flex flex-col gap-3">
            {data.data.map((source) => (
              <DownloadSourceCard key={source.source} source={source} />
            ))}
          </ul>
        )}
      </QueryState>
    </Section>
  );
}

export function DataSourcesView(): ReactElement {
  const { values, update } = useSearchState(DEFAULTS);
  const canIntel = useCan('data-source:read');
  const canPoc = useCan('poc:read');
  const canDownload = useCan('download:read');
  const tabs = [
    { id: 'intelligence', label: 'Intelligence feeds', visible: canIntel === true },
    { id: 'poc', label: 'PoC discovery', visible: canPoc === true },
    { id: 'exploits', label: 'Exploit catalogs', visible: canIntel === true },
    { id: 'downloads', label: 'Download sources', visible: canDownload === true },
  ].filter((tab) => tab.visible);
  const tab = tabs.some((entry) => entry.id === values.tab)
    ? values.tab
    : (tabs[0]?.id ?? 'intelligence');
  const loading = canIntel === undefined;
  return (
    <>
      <PageHeader
        title="Data Sources"
        description="Every external source the platform collects from, its configuration, terms of use and real synchronisation history. Sources are never assumed to be available."
      />
      {!loading && tabs.length === 0 ? (
        <EmptyState
          title="No data sources available to your role"
          description="Ask an administrator for data source access."
        />
      ) : (
        <Tabs
          value={tab}
          onValueChange={(next) => {
            update({ tab: next, source: '', status: '', trigger: '', connector: '' });
          }}
        >
          <TabsList>
            {tabs.map((entry) => (
              <TabsTrigger key={entry.id} value={entry.id}>
                {entry.label}
              </TabsTrigger>
            ))}
          </TabsList>
          {canIntel === true ? (
            <TabsContent value="intelligence">
              <IntelligenceTab values={values} update={update} />
            </TabsContent>
          ) : null}
          {canPoc === true ? (
            <TabsContent value="poc">
              <PocDiscoveryTab values={values} update={update} />
            </TabsContent>
          ) : null}
          {canIntel === true ? (
            <TabsContent value="exploits">
              <ExploitCatalogsTab values={values} update={update} />
            </TabsContent>
          ) : null}
          {canDownload === true ? (
            <TabsContent value="downloads">
              <DownloadSourcesTab />
            </TabsContent>
          ) : null}
        </Tabs>
      )}
    </>
  );
}
