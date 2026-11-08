'use client';

import { AlertTriangle, Inbox, Lock, RefreshCw } from 'lucide-react';
import type { ReactElement, ReactNode } from 'react';

import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { ApiError, describeError } from '@/lib/api/client';
import { cn } from '@/lib/utils';

export function LoadingState({
  rows = 5,
  label = 'Loading',
  className,
}: {
  rows?: number;
  label?: string;
  className?: string | undefined;
}): ReactElement {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-label={label}
      className={cn('flex flex-col gap-2 py-2', className)}
    >
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton key={index} className="h-8 w-full" />
      ))}
      <span className="sr-only">{label}…</span>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  icon,
  action,
  className,
}: {
  title: string;
  description?: ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string | undefined;
}): ReactElement {
  return (
    <div
      data-testid="empty-state"
      className={cn(
        'flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border px-6 py-10 text-center',
        className,
      )}
    >
      <div className="text-muted-foreground">
        {icon ?? <Inbox className="size-6" aria-hidden="true" />}
      </div>
      <p className="text-sm font-medium">{title}</p>
      {description === undefined ? null : (
        <p className="max-w-md text-sm text-muted-foreground">{description}</p>
      )}
      {action}
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
  title,
  className,
}: {
  error: unknown;
  onRetry?: () => void;
  title?: string;
  className?: string | undefined;
}): ReactElement {
  if (error instanceof ApiError && error.status === 403) {
    return (
      <EmptyState
        className={className}
        icon={<Lock className="size-6" aria-hidden="true" />}
        title="Access restricted"
        description="Your role does not grant access to this information. Ask an administrator if you need it."
      />
    );
  }
  const correlationId = error instanceof ApiError ? error.correlationId : null;
  return (
    <div
      role="alert"
      className={cn(
        'flex flex-col items-start gap-2 rounded-lg border border-status-down/40 bg-status-down/10 p-4 text-sm',
        className,
      )}
    >
      <p className="flex items-center gap-2 font-medium text-status-down">
        <AlertTriangle className="size-4" aria-hidden="true" />
        {title ?? 'Could not load data'}
      </p>
      <p className="text-muted-foreground">{describeError(error)}</p>
      {correlationId === null ? null : (
        <p className="text-xs text-muted-foreground">
          Correlation ID: <span className="font-mono-id">{correlationId}</span>
        </p>
      )}
      {onRetry === undefined ? null : (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw aria-hidden="true" /> Try again
        </Button>
      )}
    </div>
  );
}

interface QueryLike<T> {
  readonly data: T | undefined;
  readonly error: unknown;
  readonly isPending: boolean;
  readonly isError: boolean;
  refetch: () => unknown;
}

/** Renders loading, error and empty states for a query, and the content once data arrived. */
export function QueryState<T>({
  query,
  children,
  isEmpty,
  empty,
  loading,
}: {
  query: QueryLike<T>;
  children: (data: T) => ReactNode;
  isEmpty?: (data: T) => boolean;
  empty?: ReactNode;
  loading?: ReactNode;
}): ReactNode {
  if (query.isPending) return loading ?? <LoadingState />;
  if (query.isError || query.data === undefined) {
    return (
      <ErrorState
        error={query.error}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  }
  if (isEmpty?.(query.data) === true) return empty ?? <EmptyState title="No data" />;
  return children(query.data);
}
