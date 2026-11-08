'use client';

import Link from 'next/link';
import type { ReactElement, ReactNode } from 'react';

import { Skeleton } from '@/components/ui/skeleton';
import { Tooltip } from '@/components/ui/tooltip';
import { formatNumber } from '@/lib/format';
import { cn } from '@/lib/utils';

/**
 * A headline number from a live API response. While loading it shows a skeleton and on error
 * an explicit "Unavailable" — never a placeholder number.
 */
export function StatCard({
  label,
  value,
  loading,
  error,
  hint,
  href,
  icon,
  format = formatNumber,
}: {
  label: string;
  value: number | null | undefined;
  loading: boolean;
  error?: boolean;
  hint?: ReactNode;
  href?: string;
  icon?: ReactNode;
  format?: (value: number) => string;
}): ReactElement {
  const body = (
    <div
      data-testid={`stat-${label.toLowerCase().replaceAll(/[^a-z0-9]+/g, '-')}`}
      className={cn(
        'flex h-full flex-col gap-2 rounded-xl border border-border bg-card p-4',
        href === undefined ? undefined : 'transition-colors hover:border-primary/50',
      )}
    >
      <div className="flex items-center justify-between gap-2 text-xs font-medium text-muted-foreground">
        <span>{label}</span>
        {icon}
      </div>
      {loading ? (
        <Skeleton className="h-8 w-20" />
      ) : error === true || value === undefined ? (
        <Tooltip content="The service did not return this value. See the page for details.">
          <span className="text-sm text-muted-foreground">Unavailable</span>
        </Tooltip>
      ) : (
        <span className="text-2xl font-semibold tabular-nums">
          {value === null ? '—' : format(value)}
        </span>
      )}
      {hint === undefined ? null : <span className="text-xs text-muted-foreground">{hint}</span>}
    </div>
  );
  return href === undefined ? (
    body
  ) : (
    <Link
      href={href}
      className="block focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-xl"
    >
      {body}
    </Link>
  );
}
