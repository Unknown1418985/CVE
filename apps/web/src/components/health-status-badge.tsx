import type { HealthStatus } from '@cve/contracts';
import type { ReactElement } from 'react';

import { Badge } from '@/components/ui/badge';

const LABELS: Readonly<Record<HealthStatus, string>> = {
  ok: 'Operational',
  degraded: 'Degraded',
  down: 'Unavailable',
};

const VARIANTS = {
  ok: 'success',
  degraded: 'warning',
  down: 'destructive',
} as const satisfies Record<HealthStatus, string>;

export function HealthStatusBadge({ status }: { status: HealthStatus }): ReactElement {
  return <Badge variant={VARIANTS[status]}>{LABELS[status]}</Badge>;
}
