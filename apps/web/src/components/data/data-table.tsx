'use client';

import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react';
import { useRouter } from 'next/navigation';
import type { ReactElement, ReactNode } from 'react';

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';

import { EmptyState, LoadingState } from './states';

export type SortOrder = 'asc' | 'desc';

export interface SortState {
  readonly field: string;
  readonly order: SortOrder;
}

export interface Column<T> {
  readonly id: string;
  readonly header: ReactNode;
  readonly cell: (row: T) => ReactNode;
  /** API sort field; makes the header a sort toggle. */
  readonly sortField?: string;
  readonly className?: string;
}

export function DataTable<T>({
  columns,
  rows,
  getRowKey,
  caption,
  sort,
  onSortChange,
  rowHref,
  loading = false,
  fetching = false,
  emptyTitle = 'No results',
  emptyDescription,
}: {
  columns: readonly Column<T>[];
  rows: readonly T[] | undefined;
  getRowKey: (row: T) => string;
  caption: string;
  sort?: SortState;
  onSortChange?: (sort: SortState) => void;
  rowHref?: (row: T) => string | undefined;
  loading?: boolean;
  fetching?: boolean;
  emptyTitle?: string;
  emptyDescription?: ReactNode;
}): ReactElement {
  const router = useRouter();
  if (loading || rows === undefined) return <LoadingState rows={6} label={`Loading ${caption}`} />;
  if (rows.length === 0) return <EmptyState title={emptyTitle} description={emptyDescription} />;

  const toggle = (field: string): void => {
    if (onSortChange === undefined) return;
    onSortChange(
      sort?.field === field
        ? { field, order: sort.order === 'asc' ? 'desc' : 'asc' }
        : { field, order: 'desc' },
    );
  };

  return (
    <div aria-busy={fetching} className={cn('transition-opacity', fetching ? 'opacity-60' : undefined)}>
      <Table>
        <caption className="sr-only">{caption}</caption>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            {columns.map((column) => {
              const active = column.sortField !== undefined && sort?.field === column.sortField;
              const ariaSort = active ? (sort.order === 'asc' ? 'ascending' : 'descending') : undefined;
              return (
                <TableHead key={column.id} className={column.className} aria-sort={ariaSort}>
                  {column.sortField === undefined || onSortChange === undefined ? (
                    column.header
                  ) : (
                    <button
                      type="button"
                      className="inline-flex items-center gap-1 rounded hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      onClick={() => {
                        toggle(column.sortField ?? column.id);
                      }}
                    >
                      {column.header}
                      {active ? (
                        sort.order === 'asc' ? (
                          <ArrowUp className="size-3.5" aria-hidden="true" />
                        ) : (
                          <ArrowDown className="size-3.5" aria-hidden="true" />
                        )
                      ) : (
                        <ArrowUpDown className="size-3.5 opacity-50" aria-hidden="true" />
                      )}
                    </button>
                  )}
                </TableHead>
              );
            })}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => {
            const href = rowHref?.(row);
            return (
              <TableRow
                key={getRowKey(row)}
                className={href === undefined ? undefined : 'cursor-pointer'}
                onClick={
                  href === undefined
                    ? undefined
                    : (event) => {
                        // Links and buttons inside the row handle their own clicks.
                        if ((event.target as HTMLElement).closest('a,button,input,select,label')) return;
                        router.push(href);
                      }
                }
              >
                {columns.map((column) => (
                  <TableCell key={column.id} className={column.className}>
                    {column.cell(row)}
                  </TableCell>
                ))}
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
