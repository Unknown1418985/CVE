import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import type { ReactElement, ReactNode } from 'react';

import { AppShell } from '@/components/layout/app-shell';
import { readSession } from '@/lib/auth/session';
import { getServerEnv } from '@/lib/env';

// Every platform page depends on the signed-in user.
export const dynamic = 'force-dynamic';

export default async function PlatformLayout({ children }: { children: ReactNode }): Promise<ReactElement> {
  const session = readSession(getServerEnv(), await cookies());
  if (session === null) redirect('/session/login');
  return <AppShell>{children}</AppShell>;
}
