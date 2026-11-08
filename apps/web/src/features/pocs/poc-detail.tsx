'use client';

import { ArrowLeft, RefreshCw, TriangleAlert } from 'lucide-react';
import Link from 'next/link';
import type { ReactElement } from 'react';

import { ConfirmDialog } from '@/components/data/confirm-dialog';
import { DataTable } from '@/components/data/data-table';
import { ExternalLink } from '@/components/data/links';
import { DetailList, PageHeader, Section } from '@/components/data/page-header';
import { EmptyState, ErrorState, LoadingState, QueryState } from '@/components/data/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useCan } from '@/features/auth/use-me';
import {
  formatBytes,
  formatDate,
  formatDateTime,
  formatNumber,
  humanize,
  shortHash,
} from '@/lib/format';

import { usePocArtifacts, usePocAssociations, usePocRepository, useRepositoryCommits } from './api';
import { useTriggerDiscovery } from './mutations';
import { ARTIFACT_COLUMNS, ASSOCIATION_COLUMNS } from './poc-repository';

export function UntrustedNotice(): ReactElement {
  return (
    <p className="flex items-start gap-2 rounded-md border border-status-degraded/40 bg-status-degraded/10 p-3 text-xs text-muted-foreground">
      <TriangleAlert className="mt-0.5 size-4 shrink-0 text-status-degraded" aria-hidden="true" />
      Names, descriptions and file paths are written by the repository owner. They are shown as
      plain text and never trusted on their own. Nothing here is executed.
    </p>
  );
}

export function PocDetail({ repositoryId }: { repositoryId: string }): ReactElement {
  const repository = usePocRepository(repositoryId);
  const commits = useRepositoryCommits(repositoryId);
  const associations = usePocAssociations({ repositoryId, pageSize: 50 });
  const artifacts = usePocArtifacts({ repositoryId, pageSize: 25 });
  const canManage = useCan('poc:manage');
  const discovery = useTriggerDiscovery();
  const back = (
    <Link href="/pocs" className="inline-flex items-center gap-1 hover:text-foreground">
      <ArrowLeft className="size-3" aria-hidden="true" /> PoC Repository
    </Link>
  );

  if (repository.isPending)
    return (
      <>
        <PageHeader eyebrow={back} title="Repository" />
        <LoadingState rows={8} />
      </>
    );
  if (repository.isError) {
    return (
      <>
        <PageHeader eyebrow={back} title="Repository" />
        {repository.error.isNotFound ? (
          <EmptyState title="Repository not found" />
        ) : (
          <ErrorState
            error={repository.error}
            onRetry={() => {
              void repository.refetch();
            }}
          />
        )}
      </>
    );
  }
  const repo = repository.data.data;
  return (
    <>
      <PageHeader
        eyebrow={back}
        title={repo.fullName}
        description={<ExternalLink href={repo.url} />}
        actions={
          canManage === true ? (
            <ConfirmDialog
              trigger={
                <Button variant="outline">
                  <RefreshCw aria-hidden="true" /> Re-inspect
                </Button>
              }
              title="Re-inspect repository"
              description="Queue a discovery job that refreshes this repository's metadata and latest commit listing from GitHub. No file content is fetched."
              confirmLabel="Queue job"
              onConfirm={() => discovery.mutateAsync({ mode: 'repository', repositoryId: repo.id })}
            />
          ) : undefined
        }
      />
      <UntrustedNotice />
      <Section title="Repository">
        <div className="flex flex-col gap-4">
          <p className="text-sm whitespace-pre-line">{repo.description ?? 'No description.'}</p>
          {repo.topics.length === 0 ? null : (
            <div className="flex flex-wrap gap-1">
              {repo.topics.map((topic) => (
                <Badge key={topic} variant="outline">
                  {topic}
                </Badge>
              ))}
            </div>
          )}
          <DetailList
            items={[
              { label: 'Owner', value: `${repo.owner.login} (${humanize(repo.owner.type)})` },
              { label: 'Status', value: humanize(repo.status) },
              { label: 'Language', value: repo.language ?? '—' },
              {
                label: 'Stars / forks',
                value: `${formatNumber(repo.stars)} / ${formatNumber(repo.forks)}`,
              },
              {
                label: 'Fork of',
                value: repo.parentFullName ?? (repo.isFork ? 'Unknown parent' : 'Not a fork'),
              },
              { label: 'Archived', value: repo.isArchived ? 'Yes' : 'No' },
              { label: 'Size', value: formatBytes(repo.sizeKb * 1024) },
              { label: 'Created at source', value: formatDate(repo.sourceCreatedAt) },
              { label: 'Last push', value: formatDateTime(repo.sourcePushedAt) },
              { label: 'Discovered by', value: humanize(repo.discoveredBy) },
              { label: 'First discovered', value: formatDateTime(repo.firstDiscoveredAt) },
              { label: 'Last inspected', value: formatDateTime(repo.lastInspectedAt) },
              {
                label: 'Latest commit',
                value:
                  repo.latestCommit === null ? (
                    '—'
                  ) : (
                    <span className="font-mono-id">{shortHash(repo.latestCommit.sha, 12)}</span>
                  ),
              },
            ]}
          />
        </div>
      </Section>
      <Section
        title="CVE associations"
        description="Confidence is scored from bounded signals; discovery never confirms on its own."
      >
        {associations.isError ? (
          <ErrorState
            error={associations.error}
            onRetry={() => {
              void associations.refetch();
            }}
          />
        ) : (
          <DataTable
            caption="CVE associations"
            columns={ASSOCIATION_COLUMNS.filter((column) => column.id !== 'repository')}
            rows={associations.data?.data}
            loading={associations.isPending}
            getRowKey={(row) => row.id}
            emptyTitle="No associations"
          />
        )}
      </Section>
      <Section
        title="Artifacts"
        description="One snapshot per observed commit. A new commit starts unverified."
      >
        {artifacts.isError ? (
          <ErrorState
            error={artifacts.error}
            onRetry={() => {
              void artifacts.refetch();
            }}
          />
        ) : (
          <DataTable
            caption="Artifacts"
            columns={ARTIFACT_COLUMNS}
            rows={artifacts.data?.data}
            loading={artifacts.isPending}
            getRowKey={(row) => row.id}
            rowHref={(row) => `/pocs/artifacts/${row.id}`}
            emptyTitle="No artifacts recorded"
          />
        )}
      </Section>
      <Section
        title="Commit history"
        description="Head commits observed by the PoC Service. Committer dates are set by the committer."
      >
        <QueryState
          query={commits}
          isEmpty={(data) => data.data.length === 0}
          empty={<EmptyState title="No commits observed" />}
        >
          {(data) => (
            <Table>
              <caption className="sr-only">Commits</caption>
              <TableHeader>
                <TableRow>
                  <TableHead>Commit</TableHead>
                  <TableHead>Tree</TableHead>
                  <TableHead>Committed</TableHead>
                  <TableHead>Observed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.data.map((commit) => (
                  <TableRow key={commit.sha}>
                    <TableCell className="font-mono-id text-xs">{commit.sha}</TableCell>
                    <TableCell className="font-mono-id text-xs text-muted-foreground">
                      {shortHash(commit.treeSha, 12)}
                    </TableCell>
                    <TableCell>{formatDateTime(commit.committedAt)}</TableCell>
                    <TableCell>{formatDateTime(commit.observedAt)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </QueryState>
      </Section>
    </>
  );
}
