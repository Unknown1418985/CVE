import type { ReactElement } from 'react';

export default function Loading(): ReactElement {
  return (
    <div role="status" aria-live="polite" className="text-sm text-muted-foreground">
      Loading…
    </div>
  );
}
