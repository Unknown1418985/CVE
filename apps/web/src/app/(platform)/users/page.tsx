import type { Metadata } from 'next';
import type { ReactElement } from 'react';

import { UserManagementView } from '@/features/users/user-management';

export const metadata: Metadata = { title: 'User Management' };

export default function UsersPage(): ReactElement {
  return <UserManagementView />;
}
