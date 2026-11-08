import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import type { ReactElement } from 'react';

import { DownloadArtifactDetailView } from '@/features/downloads/artifact-detail';
import { isUuid } from '@/lib/ids';

export const metadata: Metadata = { title: 'Stored Artifact' };

export default async function DownloadArtifactPage({ params }: PageProps<'/downloads/artifacts/[artifactId]'>): Promise<ReactElement> {
  const { artifactId } = await params;
  if (!isUuid(artifactId)) notFound();
  return <DownloadArtifactDetailView artifactId={artifactId} />;
}
