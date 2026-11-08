'use client';

import type { ReactElement } from 'react';

export default function ErrorPage({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}): ReactElement {
  return (
    <div role="alert" className="mx-auto max-w-xl rounded-xl border border-border bg-card p-6">
      <h1 className="text-lg font-semibold">Something went wrong</h1>
      <p className="mt-2 text-sm text-muted-foreground">
        The page could not be rendered. The error has been recorded by the server.
      </p>
      <button
        type="button"
        onClick={reset}
        className="mt-4 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground"
      >
        Try again
      </button>
    </div>
  );
}
