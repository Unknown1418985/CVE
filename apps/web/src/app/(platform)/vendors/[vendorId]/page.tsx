import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import type { ReactElement } from 'react';

import { VendorDetail } from '@/features/assets/vendor-detail';
import { isUuid } from '@/lib/ids';

export const metadata: Metadata = { title: 'Vendor' };

export default async function VendorPage({ params }: PageProps<'/vendors/[vendorId]'>): Promise<ReactElement> {
  const { vendorId } = await params;
  if (!isUuid(vendorId)) notFound();
  return <VendorDetail vendorId={vendorId} />;
}
