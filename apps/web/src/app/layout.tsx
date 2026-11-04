import type { Metadata } from 'next';
import type { ReactElement, ReactNode } from 'react';

import { AppShell } from '@/components/app-shell';

import './globals.css';

export const metadata: Metadata = {
  title: 'CVE Intelligence Platform',
  description: 'Self-hosted vulnerability intelligence platform.',
};

export default function RootLayout({ children }: { children: ReactNode }): ReactElement {
  return (
    <html lang="en" className="dark">
      <body className="antialiased">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
