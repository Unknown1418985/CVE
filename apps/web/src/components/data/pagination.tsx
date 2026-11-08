'use client';

import type { PaginationMeta } from '@cve/contracts';
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react';
import type { ReactElement } from 'react';

import { Button } from '@/components/ui/button';
import { Select } from '@/components/ui/select';
import { formatNumber } from '@/lib/format';

const PAGE_SIZES = [10, 25, 50, 100] as const;

export function Pagination({
  meta,
  onPageChange,
  onPageSizeChange,
}: {
  meta: PaginationMeta;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
}): ReactElement {
  const first = meta.totalItems === 0 ? 0 : (meta.page - 1) * meta.pageSize + 1;
  const last = Math.min(meta.page * meta.pageSize, meta.totalItems);
  const lastPage = Math.max(1, meta.totalPages);
  return (
    <nav
      aria-label="Pagination"
      className="flex flex-col gap-3 border-t border-border pt-3 text-sm sm:flex-row sm:items-center sm:justify-between"
    >
      <p className="text-muted-foreground" data-testid="pagination-summary">
        {meta.totalItems === 0
          ? 'No results'
          : `${formatNumber(first)}–${formatNumber(last)} of ${formatNumber(meta.totalItems)}`}
      </p>
      <div className="flex flex-wrap items-center gap-2">
        {onPageSizeChange === undefined ? null : (
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            Rows
            <Select
              aria-label="Rows per page"
              className="w-20"
              value={String(meta.pageSize)}
              onChange={(event) => {
                onPageSizeChange(Number(event.target.value));
              }}
              options={PAGE_SIZES.map((size) => ({ value: String(size), label: String(size) }))}
            />
          </label>
        )}
        <Button variant="outline" size="icon" aria-label="First page" disabled={meta.page <= 1} onClick={() => { onPageChange(1); }}>
          <ChevronsLeft aria-hidden="true" />
        </Button>
        <Button variant="outline" size="icon" aria-label="Previous page" disabled={meta.page <= 1} onClick={() => { onPageChange(meta.page - 1); }}>
          <ChevronLeft aria-hidden="true" />
        </Button>
        <span className="px-1 text-xs text-muted-foreground tabular-nums">
          Page {formatNumber(meta.page)} of {formatNumber(lastPage)}
        </span>
        <Button variant="outline" size="icon" aria-label="Next page" disabled={meta.page >= lastPage} onClick={() => { onPageChange(meta.page + 1); }}>
          <ChevronRight aria-hidden="true" />
        </Button>
        <Button variant="outline" size="icon" aria-label="Last page" disabled={meta.page >= lastPage} onClick={() => { onPageChange(lastPage); }}>
          <ChevronsRight aria-hidden="true" />
        </Button>
      </div>
    </nav>
  );
}
