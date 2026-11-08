'use client';

import {
  ASSOCIATION_SORT_FIELDS,
  RECORD_SEVERITIES,
  type CveProductAssociation,
  type ProductHistoryEntry,
  type VersionRange,
} from '@cve/contracts';
import { ArrowLeft } from 'lucide-react';
import Link from 'next/link';
import type { ReactElement } from 'react';

import { DataTable, type Column, type SortOrder } from '@/components/data/data-table';
import {
  FilterBar,
  FilterField,
  MultiSelectFilter,
  SelectFilter,
  optionsFrom,
} from '@/components/data/filters';
import { CveLink, ExternalLink, InternalLink } from '@/components/data/links';
import { DetailList, PageHeader, Section } from '@/components/data/page-header';
import { Pagination } from '@/components/data/pagination';
import { EmptyState, ErrorState, LoadingState } from '@/components/data/states';
import { KevBadge, SeverityBadge } from '@/components/data/status-badges';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { intValue, listValue, useSearchState } from '@/hooks/use-search-state';
import { formatDate, formatDateTime, formatPercent, humanize } from '@/lib/format';

import { useProduct, useProductHistory, useProductVulnerabilities } from './api';

const DEFAULTS = {
  tab: 'vulnerabilities',
  severity: '',
  kev: '',
  status: '',
  version: '',
  includeWithdrawn: '',
  sort: 'cvssScore',
  order: 'desc',
  page: '1',
  pageSize: '25',
} as const;

export function formatRanges(ranges: readonly VersionRange[]): string {
  if (ranges.length === 0) return '—';
  return ranges
    .map((range) => {
      if (range.version !== null) return `= ${range.version}`;
      const parts = [
        range.versionStartIncluding === null ? null : `≥ ${range.versionStartIncluding}`,
        range.versionStartExcluding === null ? null : `> ${range.versionStartExcluding}`,
        range.versionEndIncluding === null ? null : `≤ ${range.versionEndIncluding}`,
        range.versionEndExcluding === null ? null : `< ${range.versionEndExcluding}`,
      ].filter((part) => part !== null);
      const text = parts.length === 0 ? 'all versions' : parts.join(' ');
      return range.status === 'affected' ? text : `${text} (${range.status})`;
    })
    .join('; ');
}

const VULN_COLUMNS: readonly Column<CveProductAssociation>[] = [
  { id: 'cve', header: 'CVE', sortField: 'cveId', cell: (row) => <CveLink cveId={row.cveId} /> },
  {
    id: 'severity',
    header: 'Severity',
    sortField: 'cvssScore',
    cell: (row) =>
      row.cve === null ? (
        <Badge variant="muted">No CVE facts yet</Badge>
      ) : (
        <SeverityBadge severity={row.cve.severity} score={row.cve.cvssScore} />
      ),
  },
  {
    id: 'epss',
    header: 'EPSS',
    sortField: 'epssScore',
    className: 'text-right',
    cell: (row) => <span className="tabular-nums">{formatPercent(row.cve?.epssScore)}</span>,
  },
  { id: 'kev', header: 'KEV', cell: (row) => (row.cve?.inKev === true ? <KevBadge inKev /> : '—') },
  {
    id: 'ranges',
    header: 'Affected versions',
    className: 'max-w-xs',
    cell: (row) => <span className="text-xs">{formatRanges(row.ranges)}</span>,
  },
  {
    id: 'versionAffected',
    header: 'Version check',
    cell: (row) =>
      row.versionAffected === undefined ? (
        '—'
      ) : row.versionAffected === null ? (
        <Badge variant="muted">Unknown</Badge>
      ) : row.versionAffected ? (
        <Badge variant="destructive">Affected</Badge>
      ) : (
        <Badge variant="success">Not affected</Badge>
      ),
  },
  {
    id: 'source',
    header: 'Source',
    cell: (row) => (
      <div className="flex flex-col text-xs">
        {row.sourceUrl === null ? (
          row.source
        ) : (
          <ExternalLink href={row.sourceUrl}>{row.source}</ExternalLink>
        )}
        {row.withdrawnAt === null ? null : (
          <span className="text-muted-foreground">Withdrawn {formatDate(row.withdrawnAt)}</span>
        )}
      </div>
    ),
  },
  {
    id: 'firstSeen',
    header: 'First seen',
    sortField: 'firstSeenAt',
    cell: (row) => formatDate(row.firstSeenAt),
  },
];

const HISTORY_COLUMNS: readonly Column<ProductHistoryEntry>[] = [
  { id: 'when', header: 'When', cell: (row) => formatDateTime(row.occurredAt) },
  { id: 'cve', header: 'CVE', cell: (row) => <CveLink cveId={row.cveId} /> },
  {
    id: 'change',
    header: 'Change',
    cell: (row) => (
      <Badge
        variant={row.change === 'withdrawn' ? 'muted' : row.change === 'added' ? 'warning' : 'info'}
      >
        {humanize(row.change)}
      </Badge>
    ),
  },
  {
    id: 'ranges',
    header: 'Ranges',
    cell: (row) => <span className="text-xs">{formatRanges(row.ranges)}</span>,
  },
  { id: 'source', header: 'Source', cell: (row) => `${row.source} (${row.sourceRecordId})` },
];

export function ProductDetail({ productId }: { productId: string }): ReactElement {
  const product = useProduct(productId);
  const { values, update } = useSearchState(DEFAULTS);
  const severities = listValue(values.severity);
  const sort = (ASSOCIATION_SORT_FIELDS as readonly string[]).includes(values.sort)
    ? values.sort
    : 'cvssScore';
  const order: SortOrder = values.order === 'asc' ? 'asc' : 'desc';
  const page = intValue(values.page, 1);
  const pageSize = intValue(values.pageSize, 25);
  const vulnerabilities = useProductVulnerabilities(productId, {
    severity: severities,
    kev: values.kev,
    status: values.status,
    version: values.version.trim(),
    includeWithdrawn: values.includeWithdrawn,
    sort,
    order,
    page,
    pageSize,
  });
  const history = useProductHistory(productId, { page, pageSize });
  const back = (
    <Link
      href="/vendors?tab=products"
      className="inline-flex items-center gap-1 hover:text-foreground"
    >
      <ArrowLeft className="size-3" aria-hidden="true" /> Vendors & Products
    </Link>
  );

  if (product.isPending)
    return (
      <>
        <PageHeader eyebrow={back} title="Product" />
        <LoadingState rows={8} />
      </>
    );
  if (product.isError)
    return (
      <>
        <PageHeader eyebrow={back} title="Product" />
        {product.error.isNotFound ? (
          <EmptyState title="Product not found" />
        ) : (
          <ErrorState
            error={product.error}
            onRetry={() => {
              void product.refetch();
            }}
          />
        )}
      </>
    );
  const data = product.data.data;
  return (
    <>
      <PageHeader
        eyebrow={back}
        title={`${data.vendor.name} ${data.name}`}
        description={data.description ?? undefined}
      />
      <Section title="Product">
        <DetailList
          items={[
            {
              label: 'Vendor',
              value: (
                <InternalLink href={`/vendors/${data.vendor.id}`}>{data.vendor.name}</InternalLink>
              ),
            },
            { label: 'Type', value: humanize(data.type) },
            { label: 'Origin', value: humanize(data.origin) },
            { label: 'Affected CVEs', value: data.cveCount },
            {
              label: 'Website',
              value: data.website === null ? '—' : <ExternalLink href={data.website} />,
            },
            { label: 'Source', value: data.source },
            {
              label: 'CPE names',
              wide: true,
              value:
                data.cpes.length === 0 ? (
                  '—'
                ) : (
                  <ul className="flex flex-col gap-1">
                    {data.cpes.map((cpe) => (
                      <li key={cpe.id} className="font-mono-id text-xs break-all">
                        {cpe.cpe} <span className="text-muted-foreground">({cpe.source})</span>
                      </li>
                    ))}
                  </ul>
                ),
            },
            {
              label: 'Identifiers',
              wide: true,
              value:
                data.identifiers.length === 0 ? (
                  '—'
                ) : (
                  <ul className="flex flex-col gap-1">
                    {data.identifiers.map((identifier) => (
                      <li key={identifier.id} className="text-xs break-all">
                        <Badge variant="outline">{identifier.type}</Badge>{' '}
                        <span className="font-mono-id">{identifier.value}</span>
                      </li>
                    ))}
                  </ul>
                ),
            },
          ]}
        />
      </Section>
      <Tabs
        value={values.tab === 'history' ? 'history' : 'vulnerabilities'}
        onValueChange={(tab) => {
          update({ tab });
        }}
      >
        <TabsList>
          <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
          <TabsTrigger value="history">Change history</TabsTrigger>
        </TabsList>
        <TabsContent value="vulnerabilities" className="flex flex-col gap-4">
          <FilterBar>
            <MultiSelectFilter
              label="Severity"
              values={severities}
              options={optionsFrom(RECORD_SEVERITIES, humanize)}
              onChange={(severity) => {
                update({ severity });
              }}
            />
            <SelectFilter
              id="pv-kev"
              label="CISA KEV"
              value={values.kev}
              options={[
                { value: 'true', label: 'Listed' },
                { value: 'false', label: 'Not listed' },
              ]}
              onChange={(kev) => {
                update({ kev });
              }}
            />
            <SelectFilter
              id="pv-status"
              label="Status"
              value={values.status}
              options={[
                { value: 'affected', label: 'Affected' },
                { value: 'unknown', label: 'Unknown' },
                { value: 'unaffected', label: 'Unaffected' },
              ]}
              onChange={(status) => {
                update({ status });
              }}
            />
            <FilterField label="Installed version" htmlFor="pv-version" className="w-40">
              <Input
                id="pv-version"
                value={values.version}
                maxLength={128}
                placeholder="e.g. 2.4.1"
                onChange={(event) => {
                  update({ version: event.target.value.replaceAll(/\s/g, '') });
                }}
              />
            </FilterField>
            <SelectFilter
              id="pv-withdrawn"
              label="Withdrawn"
              value={values.includeWithdrawn}
              placeholder="Hide"
              options={[{ value: 'true', label: 'Include' }]}
              onChange={(includeWithdrawn) => {
                update({ includeWithdrawn });
              }}
            />
          </FilterBar>
          <section className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4">
            {vulnerabilities.isError ? (
              <ErrorState
                error={vulnerabilities.error}
                onRetry={() => {
                  void vulnerabilities.refetch();
                }}
              />
            ) : (
              <>
                <DataTable
                  caption="Product vulnerabilities"
                  columns={VULN_COLUMNS}
                  rows={vulnerabilities.data?.data}
                  loading={vulnerabilities.isPending}
                  fetching={vulnerabilities.isFetching}
                  getRowKey={(row) => row.id}
                  sort={{ field: sort, order }}
                  onSortChange={(next) => {
                    update({ sort: next.field, order: next.order });
                  }}
                  emptyTitle="No vulnerabilities match"
                />
                {vulnerabilities.data === undefined ? null : (
                  <Pagination
                    meta={vulnerabilities.data.meta}
                    onPageChange={(next) => {
                      update({ page: next });
                    }}
                    onPageSizeChange={(next) => {
                      update({ pageSize: next });
                    }}
                  />
                )}
              </>
            )}
          </section>
        </TabsContent>
        <TabsContent value="history">
          <section className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4">
            {history.isError ? (
              <ErrorState
                error={history.error}
                onRetry={() => {
                  void history.refetch();
                }}
              />
            ) : (
              <>
                <DataTable
                  caption="Association history"
                  columns={HISTORY_COLUMNS}
                  rows={history.data?.data}
                  loading={history.isPending}
                  getRowKey={(row) => row.id}
                  emptyTitle="No changes recorded"
                />
                {history.data === undefined ? null : (
                  <Pagination
                    meta={history.data.meta}
                    onPageChange={(next) => {
                      update({ page: next });
                    }}
                  />
                )}
              </>
            )}
          </section>
        </TabsContent>
      </Tabs>
    </>
  );
}
