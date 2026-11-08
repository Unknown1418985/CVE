'use client';

import { RECORD_SEVERITIES } from '@cve/contracts';
import { ArrowLeft } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type ReactElement } from 'react';

import { BarChartView } from '@/components/data/bar-chart';
import { ChartCard } from '@/components/data/chart-card';
import { DataTable } from '@/components/data/data-table';
import { ExternalLink, InternalLink } from '@/components/data/links';
import { DetailList, PageHeader, Section } from '@/components/data/page-header';
import { Pagination } from '@/components/data/pagination';
import { StatCard } from '@/components/data/stat-card';
import { EmptyState, ErrorState, LoadingState, QueryState } from '@/components/data/states';
import { SEVERITY_COLORS } from '@/components/data/status-badges';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  formatDate,
  formatDateTime,
  formatNumber,
  formatPercent,
  formatScore,
  humanize,
} from '@/lib/format';

import { useProducts, useVendor, useVendorAnalytics } from './api';
import { PRODUCT_COLUMNS } from './vendors-products';

function Analytics({ vendorId }: { vendorId: string }): ReactElement {
  const router = useRouter();
  const query = useVendorAnalytics(vendorId);
  return (
    <QueryState query={query}>
      {({ data }) => (
        <div className="flex flex-col gap-6">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <StatCard label="Affected CVEs" value={data.cveCount} loading={false} />
            <StatCard
              label="Affected products"
              value={data.affectedProductCount}
              loading={false}
              hint={`of ${formatNumber(data.productCount)} products`}
            />
            <StatCard label="In CISA KEV" value={data.kevCount} loading={false} />
            <StatCard
              label="Average CVSS"
              value={data.averageCvssScore}
              loading={false}
              format={formatScore}
            />
            <StatCard
              label="Max CVSS"
              value={data.maxCvssScore}
              loading={false}
              format={formatScore}
            />
            <StatCard
              label="Max EPSS"
              value={data.maxEpssScore}
              loading={false}
              format={(value) => formatPercent(value)}
            />
          </div>
          {data.cvesWithoutFacts > 0 ? (
            <p className="text-xs text-muted-foreground">
              {formatNumber(data.cvesWithoutFacts)} associated CVEs have no CVE Service facts yet
              and count as unknown severity.
            </p>
          ) : null}
          {data.cveCount === 0 ? (
            <EmptyState
              title="No affected CVEs"
              description="No active CVE association marks a product of this vendor as affected."
            />
          ) : (
            <div className="grid gap-6 lg:grid-cols-2">
              <ChartCard title="Affected CVEs by severity">
                <BarChartView
                  valueLabel="CVEs"
                  data={RECORD_SEVERITIES.map((severity) => ({
                    key: severity,
                    label: humanize(severity),
                    value: data.bySeverity[severity],
                    color: SEVERITY_COLORS[severity],
                  }))}
                />
              </ChartCard>
              <ChartCard title="Affected CVEs by CVE year">
                <BarChartView
                  valueLabel="CVEs"
                  color="var(--chart-1)"
                  data={[...data.byCveYear]
                    .sort((a, b) => a.year - b.year)
                    .map((entry) => ({
                      key: String(entry.year),
                      label: String(entry.year),
                      value: entry.cveCount,
                    }))}
                />
              </ChartCard>
              <ChartCard title="Most affected products">
                <BarChartView
                  horizontal
                  valueLabel="CVEs"
                  color="var(--chart-7)"
                  data={data.topProducts.map((product) => ({
                    key: product.id,
                    label: product.name,
                    value: product.cveCount,
                  }))}
                  onSelect={(datum) => {
                    router.push(`/products/${datum.key}`);
                  }}
                />
              </ChartCard>
              <ChartCard
                title="Associations by source"
                description="Which intelligence source reported the affected products."
              >
                <BarChartView
                  horizontal
                  valueLabel="CVEs"
                  color="var(--chart-3)"
                  data={data.bySource.map((entry) => ({
                    key: entry.source,
                    label: entry.source,
                    value: entry.cveCount,
                  }))}
                />
              </ChartCard>
            </div>
          )}
          {data.topProducts.length === 0 ? null : (
            <Table>
              <caption className="sr-only">Top products</caption>
              <TableHeader>
                <TableRow>
                  <TableHead>Product</TableHead>
                  <TableHead className="text-right">CVEs</TableHead>
                  <TableHead className="text-right">Critical</TableHead>
                  <TableHead className="text-right">High</TableHead>
                  <TableHead className="text-right">KEV</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.topProducts.map((product) => (
                  <TableRow key={product.id}>
                    <TableCell>
                      <InternalLink href={`/products/${product.id}`}>{product.name}</InternalLink>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatNumber(product.cveCount)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatNumber(product.criticalCount)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatNumber(product.highCount)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatNumber(product.kevCount)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          <p className="text-xs text-muted-foreground">
            Computed {formatDateTime(data.generatedAt)}.
          </p>
        </div>
      )}
    </QueryState>
  );
}

export function VendorDetail({ vendorId }: { vendorId: string }): ReactElement {
  const vendor = useVendor(vendorId);
  const [page, setPage] = useState(1);
  const products = useProducts({ vendorId, page, pageSize: 25, sort: 'cveCount', order: 'desc' });
  const back = (
    <Link href="/vendors" className="inline-flex items-center gap-1 hover:text-foreground">
      <ArrowLeft className="size-3" aria-hidden="true" /> Vendors & Products
    </Link>
  );
  if (vendor.isPending)
    return (
      <>
        <PageHeader eyebrow={back} title="Vendor" />
        <LoadingState rows={8} />
      </>
    );
  if (vendor.isError)
    return (
      <>
        <PageHeader eyebrow={back} title="Vendor" />
        {vendor.error.isNotFound ? (
          <EmptyState title="Vendor not found" />
        ) : (
          <ErrorState
            error={vendor.error}
            onRetry={() => {
              void vendor.refetch();
            }}
          />
        )}
      </>
    );
  const data = vendor.data.data;
  return (
    <>
      <PageHeader eyebrow={back} title={data.name} description={data.description ?? undefined} />
      <Section title="Vendor">
        <DetailList
          items={[
            { label: 'Slug', value: <span className="font-mono-id">{data.slug}</span> },
            { label: 'Origin', value: humanize(data.origin) },
            { label: 'Source', value: data.source },
            {
              label: 'Website',
              value: data.website === null ? '—' : <ExternalLink href={data.website} />,
            },
            { label: 'Created', value: formatDate(data.createdAt) },
            { label: 'Updated', value: formatDate(data.updatedAt) },
          ]}
        />
      </Section>
      <Section title="Vulnerability analytics">
        <Analytics vendorId={vendorId} />
      </Section>
      <Section title="Products">
        {products.isError ? (
          <ErrorState
            error={products.error}
            onRetry={() => {
              void products.refetch();
            }}
          />
        ) : (
          <div className="flex flex-col gap-3">
            <DataTable
              caption="Products"
              columns={PRODUCT_COLUMNS.filter((column) => column.id !== 'vendor')}
              rows={products.data?.data}
              loading={products.isPending}
              getRowKey={(row) => row.id}
              rowHref={(row) => `/products/${row.id}`}
              emptyTitle="No products"
            />
            {products.data === undefined ? null : (
              <Pagination meta={products.data.meta} onPageChange={setPage} />
            )}
          </div>
        )}
      </Section>
    </>
  );
}
