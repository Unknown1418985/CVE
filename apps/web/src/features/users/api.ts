'use client';

import {
  auditEventSchema,
  credentialActionLinkSchema,
  permissionDescriptionSchema,
  roleDescriptionSchema,
  userSessionSchema,
  userSummarySchema,
} from '@cve/contracts';
import { z } from 'zod';

import { apiPath, dataSchema, pageSchema, type QueryParams } from '@/lib/api/client';
import { useApiQuery } from '@/lib/api/hooks';

export const userSchema = dataSchema(userSummarySchema);
export const sessionsSchema = dataSchema(z.array(userSessionSchema));
export const revokedSchema = dataSchema(z.object({ revokedSessions: z.number().int().min(0) }));

export function useUsers(query: QueryParams, enabled = true) {
  return useApiQuery({ path: 'users', schema: pageSchema(userSummarySchema), query, enabled, keepPrevious: true });
}

export function useUser(userId: string) {
  return useApiQuery({ path: apiPath('users', userId), schema: userSchema });
}

export function useUserSessions(userId: string, enabled = true) {
  return useApiQuery({ path: apiPath('users', userId, 'sessions'), schema: sessionsSchema, enabled });
}

export function useMySessions() {
  return useApiQuery({ path: 'me/sessions', schema: sessionsSchema });
}

export function useCredentialActions() {
  return useApiQuery({ path: 'me/credentials/actions', schema: dataSchema(z.array(credentialActionLinkSchema)) });
}

export function useRoles() {
  return useApiQuery({ path: 'roles', schema: dataSchema(z.array(roleDescriptionSchema)) });
}

export function usePermissionCatalog() {
  return useApiQuery({ path: 'permissions', schema: dataSchema(z.array(permissionDescriptionSchema)) });
}

export function useAuditEvents(query: QueryParams, enabled = true) {
  return useApiQuery({ path: 'audit-logs', schema: pageSchema(auditEventSchema), query, enabled, keepPrevious: true });
}

export function useAuditEvent(eventId: string | null) {
  return useApiQuery({
    path: apiPath('audit-logs', eventId ?? 'none'),
    schema: dataSchema(auditEventSchema),
    enabled: eventId !== null,
  });
}
