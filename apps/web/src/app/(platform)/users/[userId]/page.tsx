import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import type { ReactElement } from 'react';

import { UserDetailView } from '@/features/users/user-detail';
import { isUuid } from '@/lib/ids';

export const metadata: Metadata = { title: 'User' };

export default async function UserPage({ params }: PageProps<'/users/[userId]'>): Promise<ReactElement> {
  const { userId } = await params;
  if (!isUuid(userId)) notFound();
  return <UserDetailView userId={userId} />;
}
