import type { Metadata } from 'next';
import type { ReactElement, ReactNode } from 'react';

import { AppProviders } from '@/components/providers/app-providers';

import './globals.css';

export const metadata: Metadata = {
  title: { default: 'CVE Intelligence Platform', template: '%s · CVE Intelligence Platform' },
  description: 'Self-hosted vulnerability intelligence platform.',
  referrer: 'no-referrer',
};

export default function RootLayout({ children }: { children: ReactNode }): ReactElement {
  return (
    <html lang="en" className="dark">
      <body className="antialiased">
        <AppProviders>{children}</AppProviders>
      </body>
    </html>
  );
}
