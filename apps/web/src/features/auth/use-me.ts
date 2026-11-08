'use client';

import { userProfileSchema, type Permission, type UserProfile } from '@cve/contracts';
import type { UseQueryResult } from '@tanstack/react-query';

import type { ApiError } from '@/lib/api/client';
import { dataSchema } from '@/lib/api/client';
import { useApiQuery } from '@/lib/api/hooks';

const meSchema = dataSchema(userProfileSchema);

export function useMe(): UseQueryResult<{ data: UserProfile }, ApiError> {
  return useApiQuery({ path: 'me', schema: meSchema });
}

/**
 * Whether the signed-in user holds a permission, according to the Identity Service. `undefined`
 * while the profile loads. The UI hides actions the user cannot perform; every service still
 * enforces the same permission on the request.
 */
export function useCan(permission: Permission): boolean | undefined {
  const me = useMe();
  if (me.data === undefined) return me.isError ? false : undefined;
  return me.data.data.permissions.includes(permission);
}

export function usePermissions(): ReadonlySet<Permission> | undefined {
  const me = useMe();
  return me.data === undefined ? undefined : new Set(me.data.data.permissions);
}
