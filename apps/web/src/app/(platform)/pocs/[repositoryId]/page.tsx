import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import type { ReactElement } from 'react';

import { PocDetail } from '@/features/pocs/poc-detail';
import { isUuid } from '@/lib/ids';

export const metadata: Metadata = { title: 'PoC Details' };

export default async function PocDetailPage({
  params,
}: PageProps<'/pocs/[repositoryId]'>): Promise<ReactElement> {
  const { repositoryId } = await params;
  if (!isUuid(repositoryId)) notFound();
  return <PocDetail repositoryId={repositoryId} />;
}
