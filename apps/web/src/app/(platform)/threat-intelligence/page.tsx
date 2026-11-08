import type { Metadata } from 'next';
import type { ReactElement } from 'react';

import { ThreatIntelligence } from '@/features/threat-intel/threat-intelligence';

export const metadata: Metadata = { title: 'Threat Intelligence' };

export default function ThreatIntelligencePage(): ReactElement {
  return <ThreatIntelligence />;
}
