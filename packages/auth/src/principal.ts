import { z } from 'zod';

import { isRole, permissionsForRoles, ROLES, type Permission, type Role } from '@cve/contracts';

/** The authenticated caller, derived from a validated Keycloak access token. */
export interface AuthenticatedPrincipal {
  /** Keycloak user ID (`sub`). */
  readonly subject: string;
  readonly username: string;
  readonly email: string | undefined;
  readonly emailVerified: boolean;
  readonly name: string | undefined;
  readonly givenName: string | undefined;
  readonly familyName: string | undefined;
  /** Platform roles only; other realm roles (e.g. `offline_access`) are dropped. */
  readonly roles: readonly Role[];
  readonly permissions: readonly Permission[];
  /** Keycloak session ID (`sid`), used for logout and session revocation. */
  readonly sessionId: string | undefined;
  readonly tokenId: string | undefined;
  /** OAuth client that requested the token (`azp`). */
  readonly clientId: string | undefined;
  readonly issuedAt: Date | undefined;
  readonly expiresAt: Date;
}

const stringClaim = z.string().min(1).max(512).optional().catch(undefined);

/** Claims the platform reads; unknown claims are ignored. */
export const accessTokenClaimsSchema = z.object({
  sub: z.string().min(1).max(255),
  exp: z.number().int().positive(),
  iat: z.number().int().positive().optional(),
  jti: stringClaim,
  sid: stringClaim,
  azp: stringClaim,
  typ: z.string().optional(),
  preferred_username: stringClaim,
  email: stringClaim,
  email_verified: z.boolean().optional().catch(undefined),
  name: stringClaim,
  given_name: stringClaim,
  family_name: stringClaim,
  /** Flat claim added by the `cve-api` client scope. */
  roles: z.array(z.string()).optional().catch(undefined),
  /** Keycloak's default claim; used when the flat claim is absent. */
  realm_access: z
    .object({ roles: z.array(z.string()).optional() })
    .optional()
    .catch(undefined),
});

export type AccessTokenClaims = z.infer<typeof accessTokenClaimsSchema>;

/** Keeps only known platform roles, in canonical order. */
export function platformRoles(values: readonly string[]): Role[] {
  const present = new Set(values.filter(isRole));
  return ROLES.filter((role) => present.has(role));
}

export function principalFromClaims(claims: AccessTokenClaims): AuthenticatedPrincipal {
  const roles = platformRoles(claims.roles ?? claims.realm_access?.roles ?? []);
  return {
    subject: claims.sub,
    username: claims.preferred_username ?? claims.sub,
    email: claims.email,
    emailVerified: claims.email_verified ?? false,
    name: claims.name,
    givenName: claims.given_name,
    familyName: claims.family_name,
    roles,
    permissions: permissionsForRoles(roles),
    sessionId: claims.sid,
    tokenId: claims.jti,
    clientId: claims.azp,
    issuedAt: claims.iat === undefined ? undefined : new Date(claims.iat * 1000),
    expiresAt: new Date(claims.exp * 1000),
  };
}

export function hasPermissions(
  principal: AuthenticatedPrincipal,
  required: readonly Permission[],
): boolean {
  return required.every((permission) => principal.permissions.includes(permission));
}

export function hasAnyRole(principal: AuthenticatedPrincipal, roles: readonly Role[]): boolean {
  return roles.some((role) => principal.roles.includes(role));
}
