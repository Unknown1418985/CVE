import type { Metadata } from 'next';
import type { ReactElement } from 'react';

import { Overview } from '@/features/overview/overview';

export const metadata: Metadata = { title: 'Overview' };

export default function OverviewPage(): ReactElement {
  return <Overview />;
}
