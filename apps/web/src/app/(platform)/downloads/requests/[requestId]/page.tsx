import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import type { ReactElement } from 'react';

import { DownloadRequestDetailView } from '@/features/downloads/request-detail';
import { isUuid } from '@/lib/ids';

export const metadata: Metadata = { title: 'Download Request' };

export default async function DownloadRequestPage({
  params,
}: PageProps<'/downloads/requests/[requestId]'>): Promise<ReactElement> {
  const { requestId } = await params;
  if (!isUuid(requestId)) notFound();
  return <DownloadRequestDetailView requestId={requestId} />;
}
