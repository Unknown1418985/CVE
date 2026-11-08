'use client';

import type { DownloadAttempt, DownloadRequestDetail } from '@cve/contracts';
import { ArrowLeft, Ban, RotateCcw } from 'lucide-react';
import Link from 'next/link';
import type { ReactElement } from 'react';

import { ConfirmDialog } from '@/components/data/confirm-dialog';
import { CveLink, ExternalLink, InternalLink } from '@/components/data/links';
import { DetailList, PageHeader, Section } from '@/components/data/page-header';
import { EmptyState, ErrorState, LoadingState } from '@/components/data/states';
import { DownloadStatusBadge } from '@/components/data/status-badges';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useCan } from '@/features/auth/use-me';
import { formatBytes, formatDateTime, formatDuration, humanize, shortHash } from '@/lib/format';

import { useDownloadRequest } from './api';
import { useCancelDownload, useRetryDownload } from './mutations';

const RETRYABLE = new Set(['failed', 'rejected', 'cancelled']);

function RequestActions({ request }: { request: DownloadRequestDetail }): ReactElement | null {
  const canSchedule = useCan('download:schedule');
  const retry = useRetryDownload();
  const cancel = useCancelDownload();
  if (canSchedule !== true) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {RETRYABLE.has(request.status) ? (
        <ConfirmDialog
          trigger={<Button variant="outline"><RotateCcw aria-hidden="true" /> Retry</Button>}
          title="Retry this download"
          description="The request is queued again with the same URL. All source, address, size and type checks run again."
          confirmLabel="Retry download"
          onConfirm={() => retry.mutateAsync({ id: request.id, version: request.version })}
        />
      ) : null}
      {request.status === 'pending' ? (
        <ConfirmDialog
          trigger={<Button variant="destructive"><Ban aria-hidden="true" /> Cancel</Button>}
          title="Cancel this download"
          description="The request will not run. You can retry it later."
          confirmLabel="Cancel download"
          destructive
          onConfirm={() => cancel.mutateAsync({ id: request.id, version: request.version })}
        />
      ) : null}
    </div>
  );
}

function Attempt({ attempt }: { attempt: DownloadAttempt }): ReactElement {
  return (
    <li className="flex flex-col gap-3 rounded-md border border-border p-4" data-testid="download-attempt">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">Attempt {attempt.attempt}</span>
          {attempt.outcome === null ? <Badge variant="info">In progress</Badge> : (
            <Badge variant={attempt.outcome === 'succeeded' ? 'success' : 'destructive'}>{humanize(attempt.outcome)}</Badge>
          )}
          {attempt.errorCode === null ? null : <Badge variant="outline">{humanize(attempt.errorCode)}</Badge>}
          {attempt.retryable === true ? <Badge variant="muted">Retryable</Badge> : null}
        </div>
        <span className="text-xs text-muted-foreground">
          {formatDateTime(attempt.startedAt)}
          {attempt.durationMs === null ? '' : ` · ${formatDuration(attempt.durationMs)}`}
        </span>
      </div>
      {attempt.error === null ? null : <p className="text-sm text-status-down">{attempt.error}</p>}
      <DetailList
        items={[
          { label: 'HTTP status', value: attempt.httpStatus ?? '—' },
          { label: 'Bytes received', value: formatBytes(attempt.bytesReceived) },
          { label: 'Declared length', value: attempt.declaredLength === null ? '—' : formatBytes(attempt.declaredLength) },
          { label: 'Declared content type', value: attempt.declaredContentType ?? '—' },
          { label: 'SHA-256', value: attempt.sha256 === null ? '—' : <span className="font-mono-id text-xs break-all">{attempt.sha256}</span>, wide: true },
        ]}
      />
      {attempt.hops.length === 0 ? null : (
        <div>
          <p className="mb-2 text-xs font-medium text-muted-foreground">Request chain (every hop checked against the source allowlist and private-address rules)</p>
          <ol className="flex flex-col gap-2">
            {attempt.hops.map((hop, index) => (
              <li key={`${hop.url}-${String(index)}`} className="rounded border border-border/60 bg-background/40 p-2 text-xs">
                <p className="font-mono-id break-all">{index + 1}. {hop.url}</p>
                <p className="mt-1 text-muted-foreground">
                  HTTP {hop.status ?? '—'} · resolved {hop.resolvedAddresses.length === 0 ? '—' : hop.resolvedAddresses.join(', ')}
                  {hop.connectedAddress === null ? '' : ` · connected ${hop.connectedAddress}`}
                </p>
                {hop.location === null ? null : <p className="font-mono-id break-all text-muted-foreground">→ {hop.location}</p>}
              </li>
            ))}
          </ol>
        </div>
      )}
    </li>
  );
}

export function DownloadRequestDetailView({ requestId }: { requestId: string }): ReactElement {
  const query = useDownloadRequest(requestId);
  const back = <Link href="/downloads" className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="size-3" aria-hidden="true" /> Download requests</Link>;
  if (query.isPending) return <><PageHeader eyebrow={back} title="Download request" /><LoadingState rows={8} /></>;
  if (query.isError) {
    return (
      <>
        <PageHeader eyebrow={back} title="Download request" />
        {query.error.isNotFound ? <EmptyState title="Request not found" /> : <ErrorState error={query.error} onRetry={() => { void query.refetch(); }} />}
      </>
    );
  }
  const request = query.data.data;
  return (
    <>
      <PageHeader
        eyebrow={back}
        title={request.sourceRepository ?? humanize(request.source)}
        description={<span className="font-mono-id text-xs break-all">{request.sourceUrl}</span>}
        actions={<RequestActions request={request} />}
      />
      <Section title="Request" actions={<DownloadStatusBadge status={request.status} />}>
        <DetailList
          items={[
            { label: 'Source', value: humanize(request.source) },
            { label: 'Trigger', value: request.trigger === 'manual' ? `Manual${request.requestedBy === null ? '' : ` by ${request.requestedBy}`}` : 'Automatic (PoC discovery event)' },
            { label: 'Priority', value: request.priority },
            { label: 'Scheduled for', value: formatDateTime(request.scheduledFor) },
            { label: 'Attempts', value: `${request.attempts} of ${request.maxAttempts}` },
            { label: 'Finished', value: request.finishedAt === null ? '—' : formatDateTime(request.finishedAt) },
            { label: 'Source URL', value: <ExternalLink href={request.sourceUrl} className="font-mono-id text-xs break-all">{request.sourceUrl}</ExternalLink>, wide: true },
            { label: 'Commit', value: request.commitSha === null ? '—' : <span className="font-mono-id text-xs">{shortHash(request.commitSha, 16)}</span> },
            {
              label: 'PoC snapshot',
              value: request.pocArtifactId === null ? '—' : <InternalLink href={`/pocs/artifacts/${request.pocArtifactId}`}>View snapshot</InternalLink>,
            },
            {
              label: 'Stored artifact',
              value: request.artifactId === null ? '—' : <InternalLink href={`/downloads/artifacts/${request.artifactId}`}>View artifact</InternalLink>,
            },
            {
              label: 'CVEs',
              value: request.cveIds.length === 0 ? '—' : <span className="flex flex-wrap gap-2">{request.cveIds.map((cveId) => <CveLink key={cveId} cveId={cveId} />)}</span>,
              wide: true,
            },
            ...(request.error === null
              ? []
              : [{ label: 'Last error', value: <span className="text-status-down">{request.errorCode === null ? '' : `${humanize(request.errorCode)}: `}{request.error}</span>, wide: true }]),
          ]}
        />
      </Section>
      <Section title="Attempts" description="Each attempt with its full redirect chain, kept for provenance.">
        {request.attemptHistory.length === 0 ? (
          <EmptyState title="Not attempted yet" description="The request is waiting for its scheduled time or a worker." />
        ) : (
          <ol className="flex flex-col gap-3">
            {[...request.attemptHistory].sort((a, b) => b.attempt - a.attempt).map((attempt) => <Attempt key={attempt.id} attempt={attempt} />)}
          </ol>
        )}
      </Section>
    </>
  );
}
