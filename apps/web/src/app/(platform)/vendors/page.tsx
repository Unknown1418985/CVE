import type { Metadata } from 'next';
import type { ReactElement } from 'react';

import { VendorsProducts } from '@/features/assets/vendors-products';

export const metadata: Metadata = { title: 'Vendors & Products' };

export default function VendorsPage(): ReactElement {
  return <VendorsProducts />;
}
