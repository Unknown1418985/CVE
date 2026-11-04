import { describe, expect, it } from 'vitest';

import {
  canAssignRole,
  isPermission,
  isRole,
  PERMISSION_DESCRIPTIONS,
  PERMISSIONS,
  permissionsForRoles,
  ROLE_PERMISSIONS,
  ROLES,
  updateProfileRequestSchema,
  updateUserRolesRequestSchema,
} from './index.js';

describe('permission catalog', () => {
  it('uses the <resource>:<action> format and describes every permission', () => {
    for (const permission of PERMISSIONS) {
      expect(permission).toMatch(/^[a-z]+(?:-[a-z]+)*:[a-z]+(?:-[a-z]+)*$/);
      expect(PERMISSION_DESCRIPTIONS[permission].length).toBeGreaterThan(0);
    }
  });

  it('follows the role hierarchy of the Keycloak composite roles', () => {
    const includes = (role: (typeof ROLES)[number], base: (typeof ROLES)[number]) =>
      ROLE_PERMISSIONS[base].every((p) => ROLE_PERMISSIONS[role].includes(p));
    expect(includes('vulnerability-researcher', 'viewer')).toBe(true);
    expect(includes('security-analyst', 'viewer')).toBe(true);
    expect(includes('administrator', 'security-analyst')).toBe(true);
    expect(includes('administrator', 'vulnerability-researcher')).toBe(true);
    expect(includes('super-admin', 'administrator')).toBe(true);
  });

  it('grants every permission to super-admin and keeps viewers read-only', () => {
    expect([...ROLE_PERMISSIONS['super-admin']].sort()).toEqual([...PERMISSIONS].sort());
    expect(ROLE_PERMISSIONS.viewer.every((p) => p.endsWith(':read'))).toBe(true);
  });

  it('keeps quarantined artifacts away from viewers and analysts', () => {
    expect(ROLE_PERMISSIONS.viewer).not.toContain('quarantine:read');
    expect(ROLE_PERMISSIONS['security-analyst']).not.toContain('quarantine:read');
    expect(ROLE_PERMISSIONS['vulnerability-researcher']).toContain('quarantine:read');
    expect(ROLE_PERMISSIONS['vulnerability-researcher']).not.toContain('quarantine:manage');
  });

  it('computes the union of role permissions', () => {
    expect(permissionsForRoles([])).toEqual([]);
    const union = permissionsForRoles(['security-analyst', 'vulnerability-researcher']);
    expect(union).toContain('asset:manage');
    expect(union).toContain('poc:manage');
    expect(union).not.toContain('user:manage');
    expect(new Set(union).size).toBe(union.length);
  });

  it('restricts privileged role assignment', () => {
    const admin = ROLE_PERMISSIONS.administrator;
    expect(canAssignRole(admin, 'security-analyst')).toBe(true);
    expect(canAssignRole(admin, 'administrator')).toBe(false);
    expect(canAssignRole(admin, 'super-admin')).toBe(false);
    expect(canAssignRole(ROLE_PERMISSIONS['super-admin'], 'super-admin')).toBe(true);
    expect(canAssignRole(ROLE_PERMISSIONS.viewer, 'viewer')).toBe(false);
  });

  it('type-guards roles and permissions', () => {
    expect(isRole('viewer')).toBe(true);
    expect(isRole('root')).toBe(false);
    expect(isPermission('audit:read')).toBe(true);
    expect(isPermission('audit:*')).toBe(false);
  });
});

describe('identity request schemas', () => {
  it('rejects unknown and empty profile updates', () => {
    expect(updateProfileRequestSchema.safeParse({}).success).toBe(false);
    expect(updateProfileRequestSchema.safeParse({ email: 'x@example.com' }).success).toBe(false);
    expect(updateProfileRequestSchema.safeParse({ timezone: 'Mars/Olympus' }).success).toBe(false);
    expect(updateProfileRequestSchema.safeParse({ firstName: '<script>' }).success).toBe(false);
    expect(
      updateProfileRequestSchema.safeParse({ timezone: 'Europe/Berlin', displayName: null })
        .success,
    ).toBe(true);
  });

  it('rejects unknown and duplicate roles', () => {
    expect(updateUserRolesRequestSchema.safeParse({ roles: ['root'] }).success).toBe(false);
    expect(updateUserRolesRequestSchema.safeParse({ roles: ['viewer', 'viewer'] }).success).toBe(
      false,
    );
    expect(updateUserRolesRequestSchema.safeParse({ roles: [] }).success).toBe(true);
  });
});
