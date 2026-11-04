import { ROLES, type Role } from './roles.js';

/**
 * Permission catalog (`<resource>:<action>`). Roles are managed in Keycloak; permissions are
 * derived from roles by this static, reviewed mapping so every service enforces the same rules
 * without calling the Identity Service on each request.
 */
export const PERMISSIONS = [
  'cve:read',
  'cve:manage',
  'analysis:read',
  'analysis:write',
  'poc:read',
  'poc:manage',
  'artifact:download',
  'quarantine:read',
  'quarantine:manage',
  'download:read',
  'download:schedule',
  'exploit:read',
  'exploit:manage',
  'asset:read',
  'asset:manage',
  'threat-intel:read',
  'data-source:read',
  'data-source:manage',
  'report:read',
  'report:create',
  'user:read',
  'user:manage',
  'role:assign',
  'role:assign-privileged',
  'session:manage',
  'audit:read',
  'settings:read',
  'settings:manage',
  'platform-health:read',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

export const PERMISSION_DESCRIPTIONS: Readonly<Record<Permission, string>> = {
  'cve:read': 'View CVE records, metrics and references',
  'cve:manage': 'Create, correct and delete CVE records',
  'analysis:read': 'View vulnerability analyses',
  'analysis:write': 'Create and update vulnerability analyses',
  'poc:read': 'View PoC metadata',
  'poc:manage': 'Register, associate and verify PoCs',
  'artifact:download': 'Download released (non-quarantined) artifacts',
  'quarantine:read': 'Inspect quarantined artifacts and scanner results',
  'quarantine:manage': 'Release or reject quarantined artifacts',
  'download:read': 'View download jobs and history',
  'download:schedule': 'Schedule artifact downloads',
  'exploit:read': 'View exploit intelligence',
  'exploit:manage': 'Manage exploit records and relationships',
  'asset:read': 'View vendors and products',
  'asset:manage': 'Manage vendors and products',
  'threat-intel:read': 'View threat intelligence (KEV, EPSS)',
  'data-source:read': 'View data source configuration and synchronisation logs',
  'data-source:manage': 'Configure data sources and trigger synchronisations',
  'report:read': 'View reports and dashboards',
  'report:create': 'Generate reports',
  'user:read': 'View platform users',
  'user:manage': 'Enable, disable and require credential updates for users',
  'role:assign': 'Grant and revoke non-privileged roles',
  'role:assign-privileged': 'Grant and revoke the Administrator and Super Admin roles',
  'session:manage': "View and revoke other users' sessions",
  'audit:read': 'View the audit log',
  'settings:read': 'View platform settings',
  'settings:manage': 'Change platform settings',
  'platform-health:read': 'View detailed platform health',
};

const VIEWER: readonly Permission[] = [
  'cve:read',
  'analysis:read',
  'poc:read',
  'exploit:read',
  'asset:read',
  'threat-intel:read',
  'report:read',
  'platform-health:read',
];

const RESEARCHER: readonly Permission[] = [
  ...VIEWER,
  'analysis:write',
  'poc:manage',
  'exploit:manage',
  'artifact:download',
  'quarantine:read',
  'download:read',
  'download:schedule',
];

const ANALYST: readonly Permission[] = [
  ...VIEWER,
  'analysis:write',
  'asset:manage',
  'artifact:download',
  'download:read',
  'data-source:read',
  'report:create',
];

const ADMINISTRATOR: readonly Permission[] = [
  ...RESEARCHER,
  ...ANALYST,
  'cve:manage',
  'quarantine:manage',
  'data-source:manage',
  'user:read',
  'user:manage',
  'role:assign',
  'session:manage',
  'audit:read',
  'settings:read',
  'settings:manage',
];

const SUPER_ADMIN: readonly Permission[] = [...ADMINISTRATOR, 'role:assign-privileged'];

/** Permissions granted by each role. Mirrors the composite roles in the Keycloak realm. */
export const ROLE_PERMISSIONS: Readonly<Record<Role, readonly Permission[]>> = {
  viewer: [...new Set(VIEWER)],
  'vulnerability-researcher': [...new Set(RESEARCHER)],
  'security-analyst': [...new Set(ANALYST)],
  administrator: [...new Set(ADMINISTRATOR)],
  'super-admin': [...new Set(SUPER_ADMIN)],
};

/** Roles that only holders of `role:assign-privileged` may grant or revoke. */
export const PRIVILEGED_ROLES: readonly Role[] = ['super-admin', 'administrator'];

export function isRole(value: string): value is Role {
  return (ROLES as readonly string[]).includes(value);
}

export function isPermission(value: string): value is Permission {
  return (PERMISSIONS as readonly string[]).includes(value);
}

/** Union of the permissions of all given roles, in catalog order. */
export function permissionsForRoles(roles: readonly Role[]): Permission[] {
  const granted = new Set<Permission>(roles.flatMap((role) => ROLE_PERMISSIONS[role]));
  return PERMISSIONS.filter((permission) => granted.has(permission));
}

/** Whether the holder of `permissions` may grant or revoke `role`. */
export function canAssignRole(permissions: readonly Permission[], role: Role): boolean {
  return PRIVILEGED_ROLES.includes(role)
    ? permissions.includes('role:assign-privileged')
    : permissions.includes('role:assign') || permissions.includes('role:assign-privileged');
}
