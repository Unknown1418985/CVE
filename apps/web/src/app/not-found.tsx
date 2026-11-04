import Link from 'next/link';
import type { ReactElement } from 'react';

export default function NotFound(): ReactElement {
  return (
    <div className="mx-auto max-w-xl rounded-xl border border-border bg-card p-6">
      <h1 className="text-lg font-semibold">Page not found</h1>
      <p className="mt-2 text-sm text-muted-foreground">
        This section does not exist or is not available yet.
      </p>
      <Link href="/" className="mt-4 inline-block text-sm text-primary hover:underline">
        Back to Overview
      </Link>
    </div>
  );
}
