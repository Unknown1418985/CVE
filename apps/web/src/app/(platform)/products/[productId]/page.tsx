import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import type { ReactElement } from 'react';

import { ProductDetail } from '@/features/assets/product-detail';
import { isUuid } from '@/lib/ids';

export const metadata: Metadata = { title: 'Product' };

export default async function ProductPage({
  params,
}: PageProps<'/products/[productId]'>): Promise<ReactElement> {
  const { productId } = await params;
  if (!isUuid(productId)) notFound();
  return <ProductDetail productId={productId} />;
}
