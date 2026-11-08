import type { Metadata } from 'next';
import type { ReactElement } from 'react';

import { DownloadManagerView } from '@/features/downloads/download-manager';

export const metadata: Metadata = { title: 'Download Manager' };

export default function DownloadManagerPage(): ReactElement {
  return <DownloadManagerView />;
}
