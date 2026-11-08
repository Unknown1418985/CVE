'use client';

import {
  PRODUCT_SORT_FIELDS,
  PRODUCT_TYPES,
  VENDOR_SORT_FIELDS,
  type ProductSummary,
  type Vendor,
} from '@cve/contracts';
import type { ReactElement } from 'react';

import { DataTable, type Column, type SortOrder } from '@/components/data/data-table';
import {
  FilterBar,
  FilterField,
  SearchFilter,
  SelectFilter,
  optionsFrom,
} from '@/components/data/filters';
import { InternalLink } from '@/components/data/links';
import { PageHeader } from '@/components/data/page-header';
import { ResultsPanel as Results, type UpdateSearch } from '@/components/data/results';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { intValue, useSearchState } from '@/hooks/use-search-state';
import { formatDate, formatNumber, humanize } from '@/lib/format';

import { useProducts, useVendors } from './api';

const DEFAULTS = {
  tab: 'vendors',
  q: '',
  origin: '',
  type: '',
  cpe: '',
  sort: '',
  order: '',
  page: '1',
  pageSize: '25',
} as const;
type Values = Record<keyof typeof DEFAULTS, string>;
type Update = UpdateSearch;

const ORIGINS = [
  { value: 'curated', label: 'Curated' },
  { value: 'discovered', label: 'Discovered from CVE data' },
];

const VENDOR_COLUMNS: readonly Column<Vendor>[] = [
  {
    id: 'name',
    header: 'Vendor',
    sortField: 'name',
    cell: (row) => (
      <div className="flex flex-col">
        <InternalLink href={`/vendors/${row.id}`} className="font-medium">
          {row.name}
        </InternalLink>
        <span className="font-mono-id text-xs text-muted-foreground">{row.slug}</span>
      </div>
    ),
  },
  {
    id: 'products',
    header: 'Products',
    sortField: 'productCount',
    className: 'text-right',
    cell: (row) => <span className="tabular-nums">{formatNumber(row.productCount)}</span>,
  },
  {
    id: 'cves',
    header: 'Affected CVEs',
    sortField: 'cveCount',
    className: 'text-right',
    cell: (row) => <span className="tabular-nums">{formatNumber(row.cveCount)}</span>,
  },
  {
    id: 'origin',
    header: 'Origin',
    cell: (row) => (
      <Badge variant={row.origin === 'curated' ? 'info' : 'muted'}>{humanize(row.origin)}</Badge>
    ),
  },
  {
    id: 'updated',
    header: 'Updated',
    sortField: 'updatedAt',
    cell: (row) => formatDate(row.updatedAt),
  },
];

export const PRODUCT_COLUMNS: readonly Column<ProductSummary>[] = [
  {
    id: 'name',
    header: 'Product',
    sortField: 'name',
    cell: (row) => (
      <div className="flex flex-col">
        <InternalLink href={`/products/${row.id}`} className="font-medium">
          {row.name}
        </InternalLink>
        <span className="font-mono-id text-xs text-muted-foreground">{row.slug}</span>
      </div>
    ),
  },
  {
    id: 'vendor',
    header: 'Vendor',
    cell: (row) => (
      <InternalLink href={`/vendors/${row.vendor.id}`}>{row.vendor.name}</InternalLink>
    ),
  },
  { id: 'type', header: 'Type', cell: (row) => humanize(row.type) },
  {
    id: 'cves',
    header: 'Affected CVEs',
    sortField: 'cveCount',
    className: 'text-right',
    cell: (row) => <span className="tabular-nums">{formatNumber(row.cveCount)}</span>,
  },
  {
    id: 'origin',
    header: 'Origin',
    cell: (row) => (
      <Badge variant={row.origin === 'curated' ? 'info' : 'muted'}>{humanize(row.origin)}</Badge>
    ),
  },
  {
    id: 'updated',
    header: 'Updated',
    sortField: 'updatedAt',
    cell: (row) => formatDate(row.updatedAt),
  },
];

function sortOf(
  values: Values,
  allowed: readonly string[],
  fallback: string,
  fallbackOrder: SortOrder,
): { field: string; order: SortOrder } {
  const field = allowed.includes(values.sort) ? values.sort : fallback;
  const order = values.order === 'asc' || values.order === 'desc' ? values.order : fallbackOrder;
  return { field, order };
}

function VendorsTab({ values, update }: { values: Values; update: Update }): ReactElement {
  const sort = sortOf(values, VENDOR_SORT_FIELDS, 'cveCount', 'desc');
  const query = useVendors({
    q: values.q,
    origin: values.origin,
    sort: sort.field,
    order: sort.order,
    page: intValue(values.page, 1),
    pageSize: intValue(values.pageSize, 25),
  });
  return (
    <div className="flex flex-col gap-4">
      <FilterBar>
        <SearchFilter
          id="vendor-q"
          label="Vendor"
          value={values.q}
          minLength={1}
          placeholder="Name or slug"
          onChange={(q) => {
            update({ q });
          }}
        />
        <SelectFilter
          id="vendor-origin"
          label="Origin"
          value={values.origin}
          options={ORIGINS}
          onChange={(origin) => {
            update({ origin });
          }}
        />
      </FilterBar>
      <Results query={query} update={update}>
        <DataTable
          caption="Vendors"
          columns={VENDOR_COLUMNS}
          rows={query.data?.data}
          loading={query.isPending}
          fetching={query.isFetching}
          getRowKey={(row) => row.id}
          rowHref={(row) => `/vendors/${row.id}`}
          sort={sort}
          onSortChange={(next) => {
            update({ sort: next.field, order: next.order });
          }}
          emptyTitle="No vendors"
          emptyDescription="Vendors are created by analysts or discovered from CVE affected-product data."
        />
      </Results>
    </div>
  );
}

function ProductsTab({ values, update }: { values: Values; update: Update }): ReactElement {
  const sort = sortOf(values, PRODUCT_SORT_FIELDS, 'cveCount', 'desc');
  const query = useProducts({
    q: values.q,
    origin: values.origin,
    type: values.type,
    cpe: values.cpe.startsWith('cpe:2.3:') ? values.cpe : undefined,
    sort: sort.field,
    order: sort.order,
    page: intValue(values.page, 1),
    pageSize: intValue(values.pageSize, 25),
  });
  return (
    <div className="flex flex-col gap-4">
      <FilterBar>
        <SearchFilter
          id="product-q"
          label="Product"
          value={values.q}
          minLength={1}
          placeholder="Name or slug"
          onChange={(q) => {
            update({ q });
          }}
        />
        <SelectFilter
          id="product-type"
          label="Type"
          value={values.type}
          options={optionsFrom(PRODUCT_TYPES, humanize)}
          onChange={(type) => {
            update({ type });
          }}
        />
        <SelectFilter
          id="product-origin"
          label="Origin"
          value={values.origin}
          options={ORIGINS}
          onChange={(origin) => {
            update({ origin });
          }}
        />
        <FilterField label="CPE 2.3 name" htmlFor="product-cpe" className="min-w-72 flex-1">
          <Input
            id="product-cpe"
            value={values.cpe}
            maxLength={512}
            placeholder="cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"
            onChange={(event) => {
              update({ cpe: event.target.value.trim() });
            }}
          />
        </FilterField>
      </FilterBar>
      <Results query={query} update={update}>
        <DataTable
          caption="Products"
          columns={PRODUCT_COLUMNS}
          rows={query.data?.data}
          loading={query.isPending}
          fetching={query.isFetching}
          getRowKey={(row) => row.id}
          rowHref={(row) => `/products/${row.id}`}
          sort={sort}
          onSortChange={(next) => {
            update({ sort: next.field, order: next.order });
          }}
          emptyTitle="No products"
        />
      </Results>
    </div>
  );
}

export function VendorsProducts(): ReactElement {
  const { values, update } = useSearchState(DEFAULTS);
  const tab = values.tab === 'products' ? 'products' : 'vendors';
  return (
    <>
      <PageHeader
        title="Vendors & Products"
        description="The Asset Service's product catalog, with CPE names, package identifiers and the CVEs that affect each product."
      />
      <Tabs
        value={tab}
        onValueChange={(next) => {
          update({ tab: next, sort: '', order: '', q: '' });
        }}
      >
        <TabsList>
          <TabsTrigger value="vendors">Vendors</TabsTrigger>
          <TabsTrigger value="products">Products</TabsTrigger>
        </TabsList>
        <TabsContent value="vendors">
          <VendorsTab values={values} update={update} />
        </TabsContent>
        <TabsContent value="products">
          <ProductsTab values={values} update={update} />
        </TabsContent>
      </Tabs>
    </>
  );
}
