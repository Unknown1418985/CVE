import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import type { ReactElement } from 'react';

import { PocArtifactDetail } from '@/features/pocs/artifact-detail';
import { isUuid } from '@/lib/ids';

export const metadata: Metadata = { title: 'PoC Artifact' };

export default async function PocArtifactPage({
  params,
}: PageProps<'/pocs/artifacts/[artifactId]'>): Promise<ReactElement> {
  const { artifactId } = await params;
  if (!isUuid(artifactId)) notFound();
  return <PocArtifactDetail artifactId={artifactId} />;
}
