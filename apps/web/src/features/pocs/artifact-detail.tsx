'use client';

import {
  ARTIFACT_VERIFICATION_STATUSES,
  canTransitionVerification,
  type ArtifactVerificationStatus,
  type PocArtifactDetail as PocArtifactDetailModel,
} from '@cve/contracts';
import { ArrowLeft, Download, FileWarning } from 'lucide-react';
import Link from 'next/link';
import { useState, type ReactElement } from 'react';

import { ConfirmDialog } from '@/components/data/confirm-dialog';
import { InternalLink } from '@/components/data/links';
import { DetailList, PageHeader, Section } from '@/components/data/page-header';
import { EmptyState, ErrorState, LoadingState, QueryState } from '@/components/data/states';
import { ArtifactSecurityStatus, VerificationBadge } from '@/components/data/status-badges';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Select } from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useCan } from '@/features/auth/use-me';
import { useDownloadArtifacts } from '@/features/downloads/api';
import { formatBytes, formatDateTime, formatNumber, humanize, shortHash } from '@/lib/format';

import { usePocArtifact, useVerificationHistory } from './api';
import { useChangeVerification, useScheduleArtifactDownload } from './mutations';
import { UntrustedNotice } from './poc-detail';

function VerificationControl({
  artifact,
}: {
  artifact: PocArtifactDetailModel;
}): ReactElement | null {
  const canManage = useCan('poc:manage');
  const canQuarantine = useCan('quarantine:manage');
  const change = useChangeVerification();
  const targets = ARTIFACT_VERIFICATION_STATUSES.filter(
    (status) =>
      canTransitionVerification(artifact.verificationStatus, status) &&
      // Leaving `malicious` requires quarantine:manage (enforced by the PoC Service too).
      (artifact.verificationStatus !== 'malicious' || canQuarantine === true),
  );
  const [target, setTarget] = useState<ArtifactVerificationStatus | ''>('');
  if (canManage !== true || targets.length === 0) return null;
  return (
    <div className="flex flex-wrap items-end gap-2">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="verification-target">Change verification</Label>
        <Select
          id="verification-target"
          className="w-48"
          value={target}
          placeholder="Select status"
          options={targets.map((status) => ({ value: status, label: humanize(status) }))}
          onChange={(event) => {
            setTarget(event.target.value as ArtifactVerificationStatus | '');
          }}
        />
      </div>
      <ConfirmDialog
        trigger={
          <Button
            disabled={target === ''}
            variant={target === 'malicious' ? 'destructive' : 'default'}
          >
            Apply
          </Button>
        }
        title={`Mark artifact as ${target === '' ? '…' : humanize(target)}`}
        description={
          target === 'malicious'
            ? 'The artifact will be hidden from users without quarantine access and any stored download is revoked from release.'
            : 'The change and its reason are recorded in the verification history.'
        }
        confirmLabel="Change status"
        destructive={target === 'malicious'}
        reasonLabel="Reason"
        onConfirm={async (reason) => {
          if (target === '') return;
          await change.mutateAsync({
            id: artifact.id,
            version: artifact.version,
            status: target,
            reason,
          });
          setTarget('');
        }}
      />
    </div>
  );
}

function StoredDownloads({ artifactId }: { artifactId: string }): ReactElement | null {
  const canRead = useCan('download:read');
  const canSchedule = useCan('download:schedule');
  const query = useDownloadArtifacts({ pocArtifactId: artifactId, pageSize: 10 }, canRead === true);
  const schedule = useScheduleArtifactDownload();
  if (canRead !== true) return null;
  return (
    <Section
      title="Stored downloads"
      description="Content downloaded by the Download Service. Every file starts in quarantine and is never executed or extracted."
      actions={
        canSchedule === true ? (
          <ConfirmDialog
            trigger={
              <Button variant="outline">
                <Download aria-hidden="true" /> Schedule download
              </Button>
            }
            title="Schedule a quarantined download"
            description="The Download Service fetches the repository archive at this commit from the allowlisted source, stores it in quarantine and scans it. It is not released automatically."
            confirmLabel="Schedule download"
            reasonLabel="Reason"
            reasonRequired={false}
            onConfirm={(reason) => schedule.mutateAsync({ pocArtifactId: artifactId, reason })}
          />
        ) : undefined
      }
    >
      <QueryState
        query={query}
        isEmpty={(data) => data.data.length === 0}
        empty={
          <EmptyState
            title="Not downloaded"
            description="No file has been stored for this artifact."
          />
        }
      >
        {(data) => (
          <ul className="flex flex-col divide-y divide-border">
            {data.data.map((download) => (
              <li
                key={download.id}
                className="flex flex-wrap items-center justify-between gap-2 py-2"
              >
                <InternalLink
                  href={`/downloads/artifacts/${download.id}`}
                  className="font-mono-id text-xs"
                >
                  sha256:{shortHash(download.sha256, 16)}
                </InternalLink>
                <ArtifactSecurityStatus
                  lifecycle={download.lifecycleStatus}
                  scan={download.scanStatus}
                  verification={download.verificationStatus}
                />
              </li>
            ))}
          </ul>
        )}
      </QueryState>
    </Section>
  );
}

export function PocArtifactDetail({ artifactId }: { artifactId: string }): ReactElement {
  const query = usePocArtifact(artifactId);
  const history = useVerificationHistory(artifactId);
  if (query.isPending)
    return (
      <>
        <PageHeader title="Artifact" />
        <LoadingState rows={8} />
      </>
    );
  if (query.isError) {
    return (
      <>
        <PageHeader title="Artifact" />
        {query.error.isNotFound ? (
          <EmptyState
            title="Artifact not found"
            description="It does not exist or is hidden from your role (malicious artifacts need quarantine access)."
          />
        ) : (
          <ErrorState
            error={query.error}
            onRetry={() => {
              void query.refetch();
            }}
          />
        )}
      </>
    );
  }
  const artifact = query.data.data;
  return (
    <>
      <PageHeader
        eyebrow={
          <Link
            href={`/pocs/${artifact.repositoryId}`}
            className="inline-flex items-center gap-1 hover:text-foreground"
          >
            <ArrowLeft className="size-3" aria-hidden="true" /> {artifact.repositoryFullName}
          </Link>
        }
        title={
          <span>
            Snapshot <span className="font-mono-id">@{shortHash(artifact.commitSha, 12)}</span>
          </span>
        }
        actions={<VerificationBadge status={artifact.verificationStatus} />}
      />
      <UntrustedNotice />
      <Section title="Verification" actions={<VerificationControl artifact={artifact} />}>
        <DetailList
          items={[
            { label: 'Status', value: <VerificationBadge status={artifact.verificationStatus} /> },
            { label: 'Updated', value: formatDateTime(artifact.verificationUpdatedAt) },
            { label: 'Updated by', value: artifact.verificationUpdatedBy ?? '—' },
            {
              label: 'Commit',
              value: <span className="font-mono-id text-xs break-all">{artifact.commitSha}</span>,
              wide: true,
            },
            {
              label: 'Content fingerprint (SHA-256 of listing)',
              value: <span className="font-mono-id text-xs break-all">{artifact.fingerprint}</span>,
              wide: true,
            },
            {
              label: 'Files',
              value: `${formatNumber(artifact.fileCount)}${artifact.listingTruncated ? ' (listing truncated)' : ''}`,
            },
            { label: 'Total size', value: formatBytes(artifact.totalBytes) },
            { label: 'Discovered', value: formatDateTime(artifact.discoveredAt) },
            {
              label: 'Duplicate',
              value:
                artifact.duplicate === null ? (
                  'No'
                ) : (
                  <InternalLink href={`/pocs/artifacts/${artifact.duplicate.ofArtifactId}`}>
                    {humanize(artifact.duplicate.kind)} duplicate of{' '}
                    {artifact.duplicate.ofRepositoryFullName} (
                    {Math.round(artifact.duplicate.similarity * 100)}%)
                  </InternalLink>
                ),
              wide: true,
            },
            {
              label: 'Risk indicators',
              value:
                artifact.riskIndicators.length === 0 ? (
                  'None'
                ) : (
                  <span className="flex flex-wrap gap-1">
                    {artifact.riskIndicators.map((indicator) => (
                      <Badge key={indicator} variant="warning">
                        {humanize(indicator)}
                      </Badge>
                    ))}
                  </span>
                ),
              wide: true,
            },
          ]}
        />
      </Section>
      <StoredDownloads artifactId={artifact.id} />
      <Section
        title="File listing"
        description="Paths come from the repository tree and are never used as file system paths."
      >
        {artifact.files.length === 0 ? (
          <EmptyState
            title="Empty snapshot"
            icon={<FileWarning className="size-6" aria-hidden="true" />}
          />
        ) : (
          <Table>
            <caption className="sr-only">Files</caption>
            <TableHeader>
              <TableRow>
                <TableHead>Path</TableHead>
                <TableHead>Category</TableHead>
                <TableHead className="text-right">Size</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {artifact.files.map((file) => (
                <TableRow key={`${file.path}-${file.blobSha}`}>
                  <TableCell className="font-mono-id text-xs break-all">{file.path}</TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        ['executable', 'archive', 'macro-document'].includes(file.category)
                          ? 'warning'
                          : 'muted'
                      }
                    >
                      {humanize(file.category)}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right tabular-nums">
                    {formatBytes(file.sizeBytes)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Section>
      <Section title="Verification history">
        <QueryState
          query={history}
          isEmpty={(data) => data.data.length === 0}
          empty={<EmptyState title="No verification decisions yet" />}
        >
          {(data) => (
            <ol className="flex flex-col gap-3">
              {data.data.map((event) => (
                <li key={event.id} className="rounded-md border border-border p-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <VerificationBadge status={event.fromStatus} /> →{' '}
                    <VerificationBadge status={event.toStatus} />
                    <span className="text-xs text-muted-foreground">
                      {event.actorUsername ?? event.actorId} · {formatDateTime(event.createdAt)}
                    </span>
                  </div>
                  <p className="mt-2 whitespace-pre-line text-muted-foreground">{event.reason}</p>
                </li>
              ))}
            </ol>
          )}
        </QueryState>
      </Section>
    </>
  );
}
