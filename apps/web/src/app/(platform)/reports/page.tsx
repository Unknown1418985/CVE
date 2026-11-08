import type { Metadata } from 'next';
import type { ReactElement } from 'react';

import { ReportsView } from '@/features/reports/reports';

export const metadata: Metadata = { title: 'Reports' };

export default function ReportsPage(): ReactElement {
  return <ReportsView />;
}
