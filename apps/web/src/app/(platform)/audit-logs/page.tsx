import type { Metadata } from 'next';
import type { ReactElement } from 'react';

import { AuditLogsView } from '@/features/audit/audit-logs';

export const metadata: Metadata = { title: 'Audit Logs' };

export default function AuditLogsPage(): ReactElement {
  return <AuditLogsView />;
}
