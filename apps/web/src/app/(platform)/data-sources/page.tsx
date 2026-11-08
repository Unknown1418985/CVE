import type { Metadata } from 'next';
import type { ReactElement } from 'react';

import { DataSourcesView } from '@/features/data-sources/data-sources';

export const metadata: Metadata = { title: 'Data Sources' };

export default function DataSourcesPage(): ReactElement {
  return <DataSourcesView />;
}
