import type { Metadata } from 'next';
import type { ReactElement } from 'react';

import { VulnerabilityAnalysis } from '@/features/analysis/vulnerability-analysis';

export const metadata: Metadata = { title: 'Vulnerability Analysis' };

export default function AnalysisPage(): ReactElement {
  return <VulnerabilityAnalysis />;
}
