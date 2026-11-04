import { z } from 'zod';

import { paginationQuerySchema } from './api.js';
import { PERMISSIONS } from './permissions.js';
import { ROLES } from './roles.js';

export const roleSchema = z.enum(ROLES);
export const permissionSchema = z.enum(PERMISSIONS);

/** IANA time zone names such as `Europe/Berlin`; validated against the runtime's zone list. */
export const timeZoneSchema = z
  .string()
  .min(1)
  .max(64)
  .refine(
    (value) => {
      try {
        new Intl.DateTimeFormat('en-US', { timeZone: value });
        return true;
      } catch {
        return false;
      }
    },
    { message: 'must be a valid IANA time zone' },
  );

const personNameSchema = z
  .string()
  .trim()
  .min(1)
  .max(100)
  .regex(/^[^<>\p{Cc}]+$/u, { message: 'contains forbidden characters' });

// ---------------------------------------------------------------------------- profile

export const userProfileSchema = z.object({
  id: z.uuid(),
  username: z.string(),
  email: z.string().nullable(),
  emailVerified: z.boolean(),
  firstName: z.string().nullable(),
  lastName: z.string().nullable(),
  displayName: z.string().nullable(),
  jobTitle: z.string().nullable(),
  timezone: z.string(),
  roles: z.array(roleSchema),
  permissions: z.array(permissionSchema),
  firstSeenAt: z.iso.datetime(),
  lastSeenAt: z.iso.datetime(),
});
export type UserProfile = z.infer<typeof userProfileSchema>;

/** `PATCH /api/v1/me`. Identity attributes (names) are written to Keycloak, the rest locally. */
export const updateProfileRequestSchema = z
  .strictObject({
    firstName: personNameSchema.optional(),
    lastName: personNameSchema.optional(),
    displayName: personNameSchema.nullable().optional(),
    jobTitle: personNameSchema.nullable().optional(),
    timezone: timeZoneSchema.optional(),
  })
  .refine((value) => Object.keys(value).length > 0, { message: 'at least one field is required' });
export type UpdateProfileRequest = z.infer<typeof updateProfileRequestSchema>;

/** Keycloak application-initiated actions the user can start for their own credentials. */
export const CREDENTIAL_ACTIONS = ['update-password', 'configure-totp'] as const;
export const credentialActionSchema = z.enum(CREDENTIAL_ACTIONS);
export type CredentialAction = z.infer<typeof credentialActionSchema>;

export const credentialActionLinkSchema = z.object({
  action: credentialActionSchema,
  /** Keycloak authorization URL; the browser adds `state`, `nonce` and PKCE parameters. */
  url: z.url(),
});
export type CredentialActionLink = z.infer<typeof credentialActionLinkSchema>;

// ---------------------------------------------------------------------------- sessions

export const userSessionSchema = z.object({
  id: z.string(),
  ipAddress: z.string().nullable(),
  startedAt: z.iso.datetime(),
  lastAccessAt: z.iso.datetime(),
  clients: z.array(z.string()),
  current: z.boolean(),
});
export type UserSession = z.infer<typeof userSessionSchema>;

export const sessionIdParamSchema = z
  .string()
  .regex(/^[A-Za-z0-9-]{8,64}$/, { message: 'invalid session ID' });

// ---------------------------------------------------------------------------- users (admin)

export const userSummarySchema = z.object({
  id: z.uuid(),
  username: z.string(),
  email: z.string().nullable(),
  firstName: z.string().nullable(),
  lastName: z.string().nullable(),
  enabled: z.boolean(),
  emailVerified: z.boolean(),
  createdAt: z.iso.datetime().nullable(),
  roles: z.array(roleSchema),
  requiredActions: z.array(z.string()),
});
export type UserSummary = z.infer<typeof userSummarySchema>;

export const listUsersQuerySchema = paginationQuerySchema.extend({
  search: z.string().trim().min(1).max(100).optional(),
});
export type ListUsersQuery = z.infer<typeof listUsersQuerySchema>;

export const updateUserRolesRequestSchema = z.strictObject({
  roles: z
    .array(roleSchema)
    .max(ROLES.length)
    .refine((roles) => new Set(roles).size === roles.length, { message: 'duplicate roles' }),
  reason: z.string().trim().min(1).max(500).optional(),
});
export type UpdateUserRolesRequest = z.infer<typeof updateUserRolesRequestSchema>;

export const updateUserStatusRequestSchema = z.strictObject({
  enabled: z.boolean(),
  reason: z.string().trim().min(1).max(500).optional(),
});
export type UpdateUserStatusRequest = z.infer<typeof updateUserStatusRequestSchema>;

export const roleDescriptionSchema = z.object({
  role: roleSchema,
  label: z.string(),
  privileged: z.boolean(),
  permissions: z.array(permissionSchema),
});
export type RoleDescription = z.infer<typeof roleDescriptionSchema>;

export const permissionDescriptionSchema = z.object({
  permission: permissionSchema,
  description: z.string(),
});
export type PermissionDescription = z.infer<typeof permissionDescriptionSchema>;

// ---------------------------------------------------------------------------- audit log

export const AUDIT_OUTCOMES = ['success', 'failure', 'denied'] as const;
export const auditOutcomeSchema = z.enum(AUDIT_OUTCOMES);
export type AuditOutcome = z.infer<typeof auditOutcomeSchema>;

export const AUDIT_ACTOR_TYPES = ['user', 'service', 'system', 'anonymous'] as const;
export const auditActorTypeSchema = z.enum(AUDIT_ACTOR_TYPES);
export type AuditActorType = z.infer<typeof auditActorTypeSchema>;

/** `<domain>.<entity>.<action>` in kebab-case, the same grammar as domain events. */
export const auditActionSchema = z
  .string()
  .max(128)
  .regex(/^[a-z]+(?:-[a-z]+)*\.[a-z]+(?:-[a-z]+)*\.[a-z]+(?:-[a-z]+)*$/);

export const auditEventSchema = z.object({
  id: z.uuid(),
  occurredAt: z.iso.datetime(),
  recordedAt: z.iso.datetime(),
  source: z.string(),
  action: auditActionSchema,
  outcome: auditOutcomeSchema,
  actorType: auditActorTypeSchema,
  actorId: z.string().nullable(),
  actorUsername: z.string().nullable(),
  resourceType: z.string().nullable(),
  resourceId: z.string().nullable(),
  ipAddress: z.string().nullable(),
  userAgent: z.string().nullable(),
  correlationId: z.string().nullable(),
  details: z.record(z.string(), z.unknown()).nullable(),
});
export type AuditEvent = z.infer<typeof auditEventSchema>;

export const listAuditEventsQuerySchema = paginationQuerySchema.extend({
  actorId: z.string().min(1).max(128).optional(),
  action: auditActionSchema.optional(),
  outcome: auditOutcomeSchema.optional(),
  source: z.string().min(1).max(64).optional(),
  resourceType: z.string().min(1).max(64).optional(),
  resourceId: z.string().min(1).max(128).optional(),
  from: z.iso.datetime().optional(),
  to: z.iso.datetime().optional(),
});
export type ListAuditEventsQuery = z.infer<typeof listAuditEventsQuerySchema>;

// ---------------------------------------------------------------------------- domain events

/** Payload of `identity.user.roles-changed`. */
export const userRolesChangedPayloadSchema = z.object({
  userId: z.uuid(),
  previousRoles: z.array(roleSchema),
  roles: z.array(roleSchema),
  changedBy: z.uuid(),
});

/** Payload of `identity.user.status-changed`. */
export const userStatusChangedPayloadSchema = z.object({
  userId: z.uuid(),
  enabled: z.boolean(),
  changedBy: z.uuid(),
});

/** Payload of `identity.session.revoked`. */
export const sessionRevokedPayloadSchema = z.object({
  userId: z.uuid(),
  /** Omitted when every session of the user was revoked. */
  sessionId: z.string().optional(),
  revokedBy: z.uuid(),
  reason: z.enum(['logout', 'user-revoked', 'admin-revoked', 'roles-changed', 'user-disabled']),
});

export const IDENTITY_EVENT_TYPES = {
  userRolesChanged: 'identity.user.roles-changed',
  userStatusChanged: 'identity.user.status-changed',
  sessionRevoked: 'identity.session.revoked',
} as const;
