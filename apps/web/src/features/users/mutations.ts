'use client';

import { userProfileSchema, type Role, type UpdateProfileRequest } from '@cve/contracts';
import { toast } from 'sonner';
import { z } from 'zod';

import { apiPath, dataSchema } from '@/lib/api/client';
import { useApiMutation } from '@/lib/api/hooks';

import { revokedSchema, userSchema } from './api';

/** 204 responses carry no body. */
const noContent = z.undefined();

function reasonBody(reason: string): { reason?: string } {
  return reason === '' ? {} : { reason };
}

export function useSetUserRoles() {
  return useApiMutation({
    schema: userSchema,
    request: (input: { userId: string; roles: readonly Role[]; reason: string }) => ({
      path: apiPath('users', input.userId, 'roles'),
      method: 'PUT',
      body: { roles: input.roles, ...reasonBody(input.reason) },
    }),
    invalidate: ['users'],
    onSuccess: () => {
      toast.success('Roles updated');
    },
  });
}

export function useSetUserStatus() {
  return useApiMutation({
    schema: userSchema,
    request: (input: { userId: string; enabled: boolean; reason: string }) => ({
      path: apiPath('users', input.userId, 'status'),
      method: 'PATCH',
      body: { enabled: input.enabled, ...reasonBody(input.reason) },
    }),
    invalidate: ['users'],
    onSuccess: (data) => {
      toast.success(data.data.enabled ? 'User enabled' : 'User disabled and signed out everywhere');
    },
  });
}

export function useRequirePasswordUpdate() {
  return useApiMutation({
    schema: userSchema,
    request: (input: { userId: string }) => ({
      path: apiPath('users', input.userId, 'credentials', 'require-password-update'),
      method: 'POST',
    }),
    invalidate: ['users'],
    onSuccess: () => {
      toast.success('Password change required at next sign-in; sessions ended');
    },
  });
}

export function useRevokeUserSession() {
  return useApiMutation({
    schema: noContent,
    request: (input: { userId: string; sessionId: string }) => ({
      path: apiPath('users', input.userId, 'sessions', input.sessionId),
      method: 'DELETE',
    }),
    invalidate: ['users'],
    onSuccess: () => {
      toast.success('Session revoked');
    },
  });
}

export function useLogoutUser() {
  return useApiMutation({
    schema: revokedSchema,
    request: (input: { userId: string }) => ({
      path: apiPath('users', input.userId, 'logout'),
      method: 'POST',
    }),
    invalidate: ['users'],
    onSuccess: (data) => {
      toast.success(`${data.data.revokedSessions} session(s) ended`);
    },
  });
}

export function useRevokeMySession() {
  return useApiMutation({
    schema: noContent,
    request: (input: { sessionId: string }) => ({
      path: apiPath('me', 'sessions', input.sessionId),
      method: 'DELETE',
    }),
    invalidate: ['me'],
    onSuccess: () => {
      toast.success('Session revoked');
    },
  });
}

export function useUpdateProfile() {
  return useApiMutation({
    schema: dataSchema(userProfileSchema),
    request: (input: UpdateProfileRequest) => ({ path: 'me', method: 'PATCH', body: input }),
    invalidate: ['me'],
    onSuccess: () => {
      toast.success('Profile saved');
    },
  });
}
