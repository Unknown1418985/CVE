import type { Role } from '@cve/contracts';

/** A user as stored in the identity provider (Keycloak). */
export interface IdpUser {
  readonly id: string;
  readonly username: string;
  readonly email: string | null;
  readonly firstName: string | null;
  readonly lastName: string | null;
  readonly enabled: boolean;
  readonly emailVerified: boolean;
  readonly createdAt: Date | null;
  readonly requiredActions: readonly string[];
}

export interface IdpSession {
  readonly id: string;
  readonly userId: string;
  readonly ipAddress: string | null;
  readonly startedAt: Date;
  readonly lastAccessAt: Date;
  readonly clients: readonly string[];
}

/** A login/logout event or an admin event recorded by Keycloak. */
export interface IdpEvent {
  readonly kind: 'user' | 'admin';
  /** Stable identifier (Keycloak's ID, or a content hash when the server omits it). */
  readonly id: string;
  readonly time: Date;
  readonly type: string;
  readonly userId: string | null;
  readonly sessionId: string | null;
  readonly clientId: string | null;
  readonly ipAddress: string | null;
  readonly error: string | null;
  readonly resourceType: string | null;
  readonly resourcePath: string | null;
  readonly details: Readonly<Record<string, string>>;
}

export interface UserPage {
  readonly users: readonly IdpUser[];
  readonly total: number;
}

export interface UserUpdate {
  readonly firstName?: string;
  readonly lastName?: string;
  readonly enabled?: boolean;
  readonly requiredActions?: readonly string[];
}

/**
 * Port to the identity provider. All credential handling stays inside Keycloak: the platform
 * never receives, stores or sets passwords.
 */
export interface IdentityProvider {
  listUsers(query: { search?: string; first: number; max: number }): Promise<UserPage>;
  /** `null` when the user does not exist. */
  getUser(userId: string): Promise<IdpUser | null>;
  updateUser(userId: string, update: UserUpdate): Promise<void>;
  /** Platform roles assigned directly to the user. */
  getDirectRoles(userId: string): Promise<Role[]>;
  /** Effective platform roles, including composites. */
  getEffectiveRoles(userId: string): Promise<Role[]>;
  addRoles(userId: string, roles: readonly Role[]): Promise<void>;
  removeRoles(userId: string, roles: readonly Role[]): Promise<void>;
  /** Enabled users that hold `role` directly. */
  listEnabledUsersWithRole(role: Role): Promise<IdpUser[]>;
  listSessions(userId: string): Promise<IdpSession[]>;
  deleteSession(sessionId: string): Promise<void>;
  logoutUser(userId: string): Promise<void>;
  /** Events at or after `since`, oldest first, at most `limit`. */
  listEvents(since: Date, limit: number): Promise<IdpEvent[]>;
  /** Readiness probe. */
  ping(timeoutMs: number): Promise<void>;
}

export const IDENTITY_PROVIDER = Symbol('IDENTITY_PROVIDER');

export class IdentityProviderError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'IdentityProviderError';
  }
}
