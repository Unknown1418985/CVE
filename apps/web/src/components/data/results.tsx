'use client';

import type { PaginationMeta } from '@cve/contracts';
import type { ReactElement, ReactNode } from 'react';

import { Input } from '@/components/ui/input';
import type { SearchPatch } from '@/hooks/use-search-state';

import type { SortOrder } from './data-table';
import { FilterField } from './filters';
import { Pagination } from './pagination';
import { ErrorState } from './states';

export type UpdateSearch = (patch: SearchPatch) => void;

export const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,19}$/;

/** A CVE ID filter value, or undefined while it is incomplete (the APIs reject partial IDs). */
export function cveFilterValue(value: string): string | undefined {
  return CVE_ID_PATTERN.test(value) ? value : undefined;
}

export interface PagedQueryLike {
  readonly data: { meta: PaginationMeta } | undefined;
  readonly isError: boolean;
  readonly error: unknown;
  refetch: () => unknown;
}

/** Card around a paginated table: shows the error state instead of the table, and pagination. */
export function ResultsPanel({
  query,
  update,
  children,
}: {
  query: PagedQueryLike;
  update: UpdateSearch;
  children: ReactNode;
}): ReactElement {
  return (
    <section className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4">
      {query.isError ? <ErrorState error={query.error} onRetry={() => { void query.refetch(); }} /> : children}
      {query.data === undefined || query.isError ? null : (
        <Pagination
          meta={query.data.meta}
          onPageChange={(page) => { update({ page }); }}
          onPageSizeChange={(pageSize) => { update({ pageSize }); }}
        />
      )}
    </section>
  );
}

export function CveIdFilter({
  id = 'filter-cve',
  value,
  update,
}: {
  id?: string;
  value: string;
  update: UpdateSearch;
}): ReactElement {
  return (
    <FilterField label="CVE ID" htmlFor={id} className="w-44">
      <Input
        id={id}
        value={value}
        placeholder="CVE-2026-1234"
        maxLength={30}
        aria-invalid={value !== '' && !CVE_ID_PATTERN.test(value)}
        onChange={(event) => { update({ cveId: event.target.value.trim().toUpperCase() }); }}
      />
    </FilterField>
  );
}

/** Sort state from the URL, restricted to the fields the endpoint accepts. */
export function sortFromValues(
  values: { sort: string; order: string },
  allowed: readonly string[],
  fallback: string,
  fallbackOrder: SortOrder = 'desc',
): { field: string; order: SortOrder } {
  const field = allowed.includes(values.sort) ? values.sort : fallback;
  const order = values.order === 'asc' || values.order === 'desc' ? values.order : fallbackOrder;
  return { field, order };
}

export function pagingFromValues(values: { page: string; pageSize: string }): { page: number; pageSize: number } {
  const page = Number.parseInt(values.page, 10);
  const pageSize = Number.parseInt(values.pageSize, 10);
  return {
    page: Number.isFinite(page) && page > 0 ? page : 1,
    pageSize: Number.isFinite(pageSize) && pageSize > 0 ? pageSize : 25,
  };
}
