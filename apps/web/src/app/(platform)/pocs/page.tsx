import type { Metadata } from 'next';
import type { ReactElement } from 'react';

import { PocRepositoryView } from '@/features/pocs/poc-repository';

export const metadata: Metadata = { title: 'PoC Repository' };

export default function PocRepositoryPage(): ReactElement {
  return <PocRepositoryView />;
}
