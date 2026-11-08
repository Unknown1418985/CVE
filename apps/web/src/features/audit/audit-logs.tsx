'use client';

import { AUDIT_OUTCOMES, type AuditEvent, type AuditOutcome } from '@cve/contracts';
import { useState, type ReactElement } from 'react';

import { DataTable, type Column } from '@/components/data/data-table';
import { FilterBar, FilterField, SearchFilter, SelectFilter, optionsFrom } from '@/components/data/filters';
import { DetailList, PageHeader } from '@/components/data/page-header';
import { ResultsPanel, pagingFromValues } from '@/components/data/results';
import { QueryState } from '@/components/data/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { dayEnd, dayStart } from '@/features/cves/api';
import { useAuditEvent, useAuditEvents } from '@/features/users/api';
import { useSearchState } from '@/hooks/use-search-state';
import { formatDateTime, humanize } from '@/lib/format';

const DEFAULTS = {
  action: '',
  outcome: '',
  source: '',
  actorId: '',
  resourceType: '',
  resourceId: '',
  from: '',
  to: '',
  page: '1',
  pageSize: '50',
} as const;

const ACTION_PATTERN = /^[a-z]+(?:-[a-z]+)*\.[a-z]+(?:-[a-z]+)*\.[a-z]+(?:-[a-z]+)*$/;

const OUTCOME_VARIANT: Readonly<Record<AuditOutcome, 'success' | 'destructive' | 'warning'>> = {
  success: 'success',
  failure: 'destructive',
  denied: 'warning',
};

export function OutcomeBadge({ outcome }: { outcome: AuditOutcome }): ReactElement {
  return <Badge variant={OUTCOME_VARIANT[outcome]} data-testid="audit-outcome">{humanize(outcome)}</Badge>;
}

function actor(event: AuditEvent): string {
  if (event.actorType !== 'user') return humanize(event.actorType);
  return event.actorUsername ?? event.actorId ?? 'Unknown user';
}

/** Trims a free-text filter and drops it when empty (the API rejects empty strings). */
function textFilter(value: string, max: number): string | undefined {
  const trimmed = value.trim();
  return trimmed === '' || trimmed.length > max ? undefined : trimmed;
}

function AuditEventDialog({ eventId, onClose }: { eventId: string | null; onClose: () => void }): ReactElement {
  const query = useAuditEvent(eventId);
  return (
    <Dialog open={eventId !== null} onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Audit entry</DialogTitle>
          <DialogDescription>Recorded by the Identity Service. Entries cannot be edited or deleted from the platform.</DialogDescription>
        </DialogHeader>
        <QueryState query={query}>
          {(data) => {
            const event = data.data;
            return (
              <div className="flex max-h-[65vh] flex-col gap-4 overflow-y-auto">
                <DetailList
                  items={[
                    { label: 'Action', value: <span className="font-mono-id text-xs">{event.action}</span> },
                    { label: 'Outcome', value: <OutcomeBadge outcome={event.outcome} /> },
                    { label: 'Source service', value: event.source },
                    { label: 'Actor', value: `${actor(event)}${event.actorId === null || event.actorType !== 'user' ? '' : ` (${event.actorId})`}` },
                    { label: 'Resource', value: event.resourceType === null ? '—' : `${event.resourceType}${event.resourceId === null ? '' : ` · ${event.resourceId}`}` },
                    { label: 'IP address', value: <span className="font-mono-id text-xs">{event.ipAddress ?? '—'}</span> },
                    { label: 'Occurred', value: formatDateTime(event.occurredAt) },
                    { label: 'Recorded', value: formatDateTime(event.recordedAt) },
                    { label: 'Correlation ID', value: <span className="font-mono-id text-xs break-all">{event.correlationId ?? '—'}</span> },
                    { label: 'User agent', value: <span className="text-xs break-all">{event.userAgent ?? '—'}</span>, wide: true },
                  ]}
                />
                <div>
                  <p className="mb-1 text-xs font-medium text-muted-foreground">Details</p>
                  {event.details === null ? <p className="text-sm text-muted-foreground">No details recorded.</p> : (
                    <pre className="max-h-72 overflow-auto rounded-md border border-border bg-background p-3 font-mono-id text-xs whitespace-pre-wrap break-all">
                      {JSON.stringify(event.details, null, 2)}
                    </pre>
                  )}
                </div>
              </div>
            );
          }}
        </QueryState>
      </DialogContent>
    </Dialog>
  );
}

export function AuditLogsView(): ReactElement {
  const { values, update } = useSearchState(DEFAULTS);
  const [openEvent, setOpenEvent] = useState<string | null>(null);
  const query = useAuditEvents({
    action: ACTION_PATTERN.test(values.action) ? values.action : undefined,
    outcome: values.outcome,
    source: textFilter(values.source, 64),
    actorId: textFilter(values.actorId, 128),
    resourceType: textFilter(values.resourceType, 64),
    resourceId: textFilter(values.resourceId, 128),
    from: dayStart(values.from),
    to: dayEnd(values.to),
    ...pagingFromValues(values),
  });
  const columns: readonly Column<AuditEvent>[] = [
    { id: 'occurred', header: 'Occurred (UTC)', cell: (row) => <span className="whitespace-nowrap text-xs">{formatDateTime(row.occurredAt)}</span> },
    {
      id: 'action',
      header: 'Action',
      cell: (row) => (
        <Button variant="link" className="h-auto p-0 font-mono-id text-xs" onClick={() => { setOpenEvent(row.id); }}>{row.action}</Button>
      ),
    },
    { id: 'outcome', header: 'Outcome', cell: (row) => <OutcomeBadge outcome={row.outcome} /> },
    { id: 'actor', header: 'Actor', cell: (row) => actor(row) },
    {
      id: 'resource',
      header: 'Resource',
      cell: (row) => (row.resourceType === null ? '—' : (
        <span className="text-xs">{row.resourceType}{row.resourceId === null ? '' : <span className="font-mono-id text-muted-foreground"> · {row.resourceId}</span>}</span>
      )),
    },
    { id: 'source', header: 'Service', cell: (row) => row.source },
    { id: 'ip', header: 'IP', cell: (row) => <span className="font-mono-id text-xs">{row.ipAddress ?? '—'}</span> },
  ];
  return (
    <>
      <PageHeader title="Audit Logs" description="Security-relevant actions across the platform: sign-ins, role and status changes, lifecycle decisions and administrative actions." />
      <FilterBar>
        <SearchFilter id="audit-action" label="Action" value={values.action} minLength={5} placeholder="identity.user.roles-changed" onChange={(action) => { update({ action: action.trim().toLowerCase() }); }} />
        <SelectFilter id="audit-outcome" label="Outcome" value={values.outcome} options={optionsFrom(AUDIT_OUTCOMES, humanize)} onChange={(outcome) => { update({ outcome }); }} />
        <SearchFilter id="audit-source" label="Service" value={values.source} minLength={1} placeholder="identity-service" onChange={(source) => { update({ source }); }} />
        <SearchFilter id="audit-actor" label="Actor ID" value={values.actorId} minLength={1} onChange={(actorId) => { update({ actorId }); }} />
        <SearchFilter id="audit-resource-type" label="Resource type" value={values.resourceType} minLength={1} onChange={(resourceType) => { update({ resourceType }); }} />
        <SearchFilter id="audit-resource-id" label="Resource ID" value={values.resourceId} minLength={1} onChange={(resourceId) => { update({ resourceId }); }} />
        <FilterField label="From" htmlFor="audit-from" className="w-40">
          <Input id="audit-from" type="date" value={values.from} onChange={(event) => { update({ from: event.target.value }); }} />
        </FilterField>
        <FilterField label="To" htmlFor="audit-to" className="w-40">
          <Input id="audit-to" type="date" value={values.to} onChange={(event) => { update({ to: event.target.value }); }} />
        </FilterField>
      </FilterBar>
      {values.action !== '' && !ACTION_PATTERN.test(values.action) ? (
        <p className="text-xs text-status-degraded">Actions have the form domain.entity.action, for example identity.user.status-changed. The filter is ignored until it matches.</p>
      ) : null}
      <ResultsPanel query={query} update={update}>
        <DataTable caption="Audit log entries" columns={columns} rows={query.data?.data} loading={query.isPending} fetching={query.isFetching}
          getRowKey={(row) => row.id} emptyTitle="No audit entries" emptyDescription="No entry matches these filters." />
      </ResultsPanel>
      <AuditEventDialog eventId={openEvent} onClose={() => { setOpenEvent(null); }} />
    </>
  );
}
