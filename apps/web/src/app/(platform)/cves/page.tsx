import type { Metadata } from 'next';
import type { ReactElement } from 'react';

import { CveExplorer } from '@/features/cves/cve-explorer';

export const metadata: Metadata = { title: 'CVE Explorer' };

export default function CveExplorerPage(): ReactElement {
  return <CveExplorer />;
}
