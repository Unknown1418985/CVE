import type { Metadata } from 'next';
import type { ReactElement } from 'react';

import { SettingsView } from '@/features/settings/settings';

export const metadata: Metadata = { title: 'Settings' };

export default function SettingsPage(): ReactElement {
  return <SettingsView />;
}
