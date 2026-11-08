import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import type { ReactElement } from 'react';

import { CveDetail } from '@/features/cves/cve-detail';

const CVE_ID = /^CVE-\d{4}-\d{4,19}$/;

export async function generateMetadata({ params }: PageProps<'/cves/[cveId]'>): Promise<Metadata> {
  const { cveId } = await params;
  return { title: decodeURIComponent(cveId).toUpperCase() };
}

export default async function CveDetailPage({ params }: PageProps<'/cves/[cveId]'>): Promise<ReactElement> {
  const cveId = decodeURIComponent((await params).cveId).toUpperCase();
  if (!CVE_ID.test(cveId)) notFound();
  return <CveDetail cveId={cveId} />;
}
