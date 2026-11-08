'use client';

import {
  canTransitionLifecycle,
  type ArtifactLifecycleStatus,
  type DownloadArtifactDetail as DownloadArtifactModel,
  type ScanResult,
} from '@cve/contracts';
import { ArrowLeft, Download, Lock, RefreshCw, ShieldCheck, ShieldX, Unlock } from 'lucide-react';
import Link from 'next/link';
import type { ReactElement } from 'react';

import { ConfirmDialog } from '@/components/data/confirm-dialog';
import { CveLink, ExternalLink, InternalLink } from '@/components/data/links';
import { DetailList, PageHeader, Section } from '@/components/data/page-header';
import { EmptyState, ErrorState, LoadingState, QueryState } from '@/components/data/states';
import { LifecycleBadge, ScanStatusBadge, VerificationBadge } from '@/components/data/status-badges';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useCan } from '@/features/auth/use-me';
import { UntrustedNotice } from '@/features/pocs/poc-detail';
import { formatBytes, formatDateTime, humanize, shortHash } from '@/lib/format';

import { useArtifactScans, useDownloadArtifact, useLifecycleHistory } from './api';
import { artifactContentUrl, useChangeLifecycle, useRescanArtifact } from './mutations';

/** Why release is not offered, mirroring the Download Service's own checks. */
export function releaseBlocker(artifact: Pick<DownloadArtifactModel, 'lifecycleStatus' | 'scanStatus' | 'verificationStatus' | 'releasable'>): string | null {
  if (!canTransitionLifecycle(artifact.lifecycleStatus, 'released')) return null;
  if (artifact.scanStatus !== 'clean') return `Release requires a clean scan (current: ${humanize(artifact.scanStatus).toLowerCase()}).`;
  if (artifact.verificationStatus === 'malicious' || artifact.verificationStatus === 'rejected') {
    return `A linked PoC artifact is marked ${artifact.verificationStatus}.`;
  }
  if (!artifact.releasable) return 'The Download Service reports this artifact as not releasable.';
  return null;
}

const ACTIONS: Readonly<Record<ArtifactLifecycleStatus, { label: string; icon: typeof Lock; description: string; destructive: boolean }>> = {
  released: {
    label: 'Release',
    icon: Unlock,
    description:
      'Users with download permission will be able to download this file as an opaque attachment. Release is not verification: the content remains untrusted and must never be run outside an isolated analysis environment.',
    destructive: false,
  },
  rejected: {
    label: 'Reject',
    icon: ShieldX,
    description: 'The file stays stored for evidence but can no longer be released or downloaded. Ordinary users will no longer see it.',
    destructive: true,
  },
  quarantined: {
    label: 'Return to quarantine',
    icon: Lock,
    description: 'The file is withdrawn from release immediately and hidden from users without quarantine access.',
    destructive: true,
  },
};

function LifecycleActions({ artifact }: { artifact: DownloadArtifactModel }): ReactElement | null {
  const canManage = useCan('quarantine:manage');
  const change = useChangeLifecycle();
  const rescan = useRescanArtifact();
  if (canManage !== true) return null;
  const blocker = releaseBlocker(artifact);
  const targets = (['released', 'quarantined', 'rejected'] as const).filter((status) => canTransitionLifecycle(artifact.lifecycleStatus, status));
  return (
    <div className="flex flex-wrap items-center gap-2" data-testid="lifecycle-actions">
      {targets.map((status) => {
        const action = ACTIONS[status];
        const Icon = action.icon;
        const disabled = status === 'released' && blocker !== null;
        return (
          <ConfirmDialog
            key={status}
            trigger={
              <Button variant={action.destructive ? 'destructive' : 'default'} disabled={disabled} title={disabled ? blocker : undefined}>
                <Icon aria-hidden="true" /> {action.label}
              </Button>
            }
            title={`${action.label} artifact sha256:${shortHash(artifact.sha256, 12)}`}
            description={action.description}
            confirmLabel={action.label}
            destructive={action.destructive}
            reasonLabel="Reason (recorded in the lifecycle history and audit log)"
            onConfirm={(reason) => change.mutateAsync({ id: artifact.id, version: artifact.version, status, reason })}
          />
        );
      })}
      <ConfirmDialog
        trigger={<Button variant="outline"><RefreshCw aria-hidden="true" /> Rescan</Button>}
        title="Scan the artifact again"
        description="Runs every configured scanner against the stored object again, for example after a signature update. The lifecycle status does not change."
        confirmLabel="Queue rescan"
        reasonLabel="Reason"
        onConfirm={(reason) => rescan.mutateAsync({ id: artifact.id, reason })}
      />
      {blocker === null || !targets.includes('released') ? null : <p className="w-full text-xs text-muted-foreground">{blocker}</p>}
    </div>
  );
}

function DownloadContent({ artifact }: { artifact: DownloadArtifactModel }): ReactElement | null {
  const canDownload = useCan('artifact:download');
  if (canDownload !== true) return null;
  if (artifact.lifecycleStatus !== 'released') {
    return (
      <Button variant="outline" disabled title="Only released artifacts can be downloaded">
        <Lock aria-hidden="true" /> Download unavailable
      </Button>
    );
  }
  return (
    <ConfirmDialog
      trigger={<Button variant="outline"><Download aria-hidden="true" /> Download file</Button>}
      title="Download untrusted content"
      description={
        <div className="flex flex-col gap-2">
          <p>
            This file was published by a third party and may contain working exploit code or malware. It is delivered as an
            opaque attachment named after its artifact ID.
          </p>
          <p>Open it only inside an isolated analysis environment. Never run it on a workstation or production system.</p>
          <p className="font-mono-id text-xs break-all">SHA-256 {artifact.sha256}</p>
        </div>
      }
      confirmLabel="I understand, download"
      onConfirm={() => {
        const link = document.createElement('a');
        link.href = artifactContentUrl(artifact.id);
        link.rel = 'noopener';
        link.download = '';
        document.body.append(link);
        link.click();
        link.remove();
        return Promise.resolve();
      }}
    />
  );
}

function ScanTable({ scans }: { scans: readonly ScanResult[] }): ReactElement {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Scanner</TableHead>
          <TableHead>Verdict</TableHead>
          <TableHead>Findings</TableHead>
          <TableHead>Engine / signatures</TableHead>
          <TableHead>Finished</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {scans.map((scan) => (
          <TableRow key={scan.id}>
            <TableCell className="font-medium">{scan.scanner === 'clamav' ? 'ClamAV' : 'YARA'}</TableCell>
            <TableCell>
              <Badge variant={scan.verdict === 'clean' ? 'success' : scan.verdict === 'malicious' ? 'destructive' : 'warning'} data-testid="scan-verdict">
                {humanize(scan.verdict)}
              </Badge>
              {scan.error === null ? null : <p className="mt-1 text-xs text-muted-foreground">{scan.error}</p>}
            </TableCell>
            <TableCell>
              {scan.findings.length === 0 ? (
                <span className="text-muted-foreground">None</span>
              ) : (
                <ul className="flex flex-col gap-0.5 text-xs">
                  {scan.findings.map((finding) => (
                    <li key={`${finding.name}-${finding.detail ?? ''}`}>
                      <span className="font-mono-id">{finding.name}</span>
                      {finding.detail === null ? null : <span className="text-muted-foreground"> · {finding.detail}</span>}
                    </li>
                  ))}
                </ul>
              )}
            </TableCell>
            <TableCell className="text-xs text-muted-foreground">
              {scan.engineVersion ?? '—'}
              {scan.signatureVersion === null ? '' : ` / ${scan.signatureVersion}`}
            </TableCell>
            <TableCell className="text-xs">{formatDateTime(scan.finishedAt)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function ScanHistory({ artifactId }: { artifactId: string }): ReactElement | null {
  const canInspect = useCan('quarantine:read');
  const query = useArtifactScans(artifactId, canInspect === true);
  if (canInspect !== true) return null;
  return (
    <Section title="Scan history" description="Every scanner run, newest first. A scanner that is not configured or failed makes the scan incomplete, never clean.">
      <QueryState query={query} isEmpty={(data) => data.data.length === 0} empty={<EmptyState title="Not scanned yet" description="The scan is queued." />}>
        {(data) => <ScanTable scans={data.data} />}
      </QueryState>
    </Section>
  );
}

function LifecycleHistory({ artifactId }: { artifactId: string }): ReactElement {
  const query = useLifecycleHistory(artifactId);
  return (
    <Section title="Lifecycle history" description="Every release, rejection and return to quarantine, with who decided and why.">
      <QueryState query={query} isEmpty={(data) => data.data.length === 0} empty={<EmptyState title="No lifecycle changes" />}>
        {(data) => (
          <ol className="flex flex-col gap-3">
            {data.data.map((event) => (
              <li key={event.id} className="flex flex-col gap-1 rounded-md border border-border p-3">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  {event.fromStatus === null ? <span className="text-muted-foreground">Stored as</span> : <LifecycleBadge status={event.fromStatus} />}
                  {event.fromStatus === null ? null : <span aria-hidden="true">→</span>}
                  <LifecycleBadge status={event.toStatus} />
                  <span className="text-xs text-muted-foreground">
                    {event.actorUsername ?? event.actorId} · {formatDateTime(event.createdAt)}
                  </span>
                </div>
                <p className="text-sm text-muted-foreground">{event.reason}</p>
              </li>
            ))}
          </ol>
        )}
      </QueryState>
    </Section>
  );
}

export function DownloadArtifactDetailView({ artifactId }: { artifactId: string }): ReactElement {
  const query = useDownloadArtifact(artifactId);
  const back = <Link href="/downloads?tab=artifacts" className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="size-3" aria-hidden="true" /> Stored artifacts</Link>;
  if (query.isPending) return <><PageHeader eyebrow={back} title="Stored artifact" /><LoadingState rows={8} /></>;
  if (query.isError) {
    return (
      <>
        <PageHeader eyebrow={back} title="Stored artifact" />
        {query.error.isNotFound ? (
          <EmptyState title="Artifact not found" description="It does not exist, or it is quarantined or rejected and your role cannot inspect quarantined content." />
        ) : (
          <ErrorState error={query.error} onRetry={() => { void query.refetch(); }} />
        )}
      </>
    );
  }
  const artifact = query.data.data;
  return (
    <>
      <PageHeader
        eyebrow={back}
        title={<span className="font-mono-id text-xl">sha256:{shortHash(artifact.sha256, 16)}</span>}
        actions={<DownloadContent artifact={artifact} />}
      />
      <UntrustedNotice />
      <Section title="Security status" description="Lifecycle, scan result and analyst verification are independent facts." actions={<LifecycleActions artifact={artifact} />}>
        <DetailList
          items={[
            { label: 'Lifecycle', value: <LifecycleBadge status={artifact.lifecycleStatus} /> },
            { label: 'Scan', value: <ScanStatusBadge status={artifact.scanStatus} /> },
            { label: 'Verification', value: <VerificationBadge status={artifact.verificationStatus} /> },
            { label: 'Last scanned', value: artifact.lastScannedAt === null ? 'Never' : formatDateTime(artifact.lastScannedAt) },
            { label: 'Released', value: artifact.releasedAt === null ? 'Never' : formatDateTime(artifact.releasedAt) },
            {
              label: 'Releasable',
              value: artifact.releasable ? (
                <span className="inline-flex items-center gap-1"><ShieldCheck className="size-4 text-status-ok" aria-hidden="true" /> Yes</span>
              ) : 'No',
            },
          ]}
        />
      </Section>
      <Section title="File">
        <DetailList
          items={[
            { label: 'SHA-256', value: <span className="font-mono-id text-xs break-all">{artifact.sha256}</span>, wide: true },
            { label: 'Size', value: formatBytes(artifact.sizeBytes) },
            { label: 'Detected type (from content)', value: humanize(artifact.detectedType) },
            { label: 'Sniffed MIME type', value: <span className="font-mono-id text-xs">{artifact.mimeType}</span> },
            { label: 'Declared content type', value: artifact.declaredContentType ?? '—' },
            {
              label: 'Original filename (untrusted)',
              value: artifact.originalFilename === null ? '—' : <span className="font-mono-id text-xs break-all">{artifact.originalFilename}</span>,
            },
            {
              label: 'Risk indicators',
              value: artifact.riskIndicators.length === 0 ? 'None' : (
                <span className="flex flex-wrap gap-1">{artifact.riskIndicators.map((indicator) => <Badge key={indicator} variant="warning">{humanize(indicator)}</Badge>)}</span>
              ),
            },
            { label: 'Storage', value: <span className="font-mono-id text-xs break-all">{artifact.storageBucket}/{artifact.storageKey}</span>, wide: true },
          ]}
        />
      </Section>
      <Section title="Provenance" description="Every download that produced this content.">
        {artifact.provenance.length === 0 ? <EmptyState title="No provenance recorded" /> : (
          <ul className="flex flex-col gap-3">
            {artifact.provenance.map((entry) => (
              <li key={entry.requestId} className="flex flex-col gap-2 rounded-md border border-border p-3 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <InternalLink href={`/downloads/requests/${entry.requestId}`}>{entry.sourceRepository ?? humanize(entry.source)}</InternalLink>
                  <span className="text-xs text-muted-foreground">Downloaded {formatDateTime(entry.downloadedAt)}</span>
                </div>
                <ExternalLink href={entry.sourceUrl} className="font-mono-id text-xs break-all">{entry.sourceUrl}</ExternalLink>
                {entry.finalUrl === null || entry.finalUrl === entry.sourceUrl ? null : (
                  <p className="font-mono-id text-xs break-all text-muted-foreground">Final URL: {entry.finalUrl}</p>
                )}
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  {entry.commitSha === null ? null : <span className="font-mono-id">commit {shortHash(entry.commitSha, 12)}</span>}
                  {entry.pocArtifactId === null ? null : <InternalLink href={`/pocs/artifacts/${entry.pocArtifactId}`}>PoC snapshot</InternalLink>}
                  {entry.cveIds.map((cveId) => <CveLink key={cveId} cveId={cveId} />)}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title="Latest scan">
        {artifact.latestScan.length === 0 ? <EmptyState title="Not scanned yet" description="The scan is queued." /> : <ScanTable scans={artifact.latestScan} />}
      </Section>
      <ScanHistory artifactId={artifact.id} />
      <LifecycleHistory artifactId={artifact.id} />
    </>
  );
}
