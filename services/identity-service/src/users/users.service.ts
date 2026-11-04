import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
} from '@nestjs/common';

import type { AuthenticatedPrincipal } from '@cve/auth';
import {
  buildPaginationMeta,
  canAssignRole,
  IDENTITY_EVENT_TYPES,
  PRIVILEGED_ROLES,
  ROLES,
  type ListUsersQuery,
  type PaginationMeta,
  type Role,
  type UpdateUserRolesRequest,
  type UpdateUserStatusRequest,
  type UserSummary,
} from '@cve/contracts';

import { AuditService } from '../audit/audit.service.js';
import { withIdpErrors } from '../common/errors.js';
import type { ActorContext } from '../common/request-context.js';
import {
  IDENTITY_PROVIDER,
  type IdentityProvider,
  type IdpUser,
} from '../keycloak/identity-provider.js';
import { SessionsService } from '../sessions/sessions.service.js';

const UPDATE_PASSWORD_ACTION = 'UPDATE_PASSWORD';
const ROLE_LOOKUP_CONCURRENCY = 10;

async function mapConcurrent<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await fn(items[index] as T);
    }
  });
  await Promise.all(workers);
  return results;
}

function toSummary(user: IdpUser, roles: readonly Role[]): UserSummary {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    enabled: user.enabled,
    emailVerified: user.emailVerified,
    createdAt: user.createdAt?.toISOString() ?? null,
    roles: [...roles],
    requiredActions: [...user.requiredActions],
  };
}

/**
 * User administration on top of Keycloak. Enforces the platform's delegation rules:
 * administrators cannot act on privileged accounts or grant privileged roles, nobody changes
 * their own roles or status, and the last enabled Super Admin cannot be demoted or disabled.
 */
@Injectable()
export class UsersService {
  constructor(
    @Inject(IDENTITY_PROVIDER) private readonly idp: IdentityProvider,
    private readonly sessions: SessionsService,
    private readonly audit: AuditService,
  ) {}

  async list(query: ListUsersQuery): Promise<{ data: UserSummary[]; meta: PaginationMeta }> {
    const page = await withIdpErrors(() =>
      this.idp.listUsers({
        ...(query.search === undefined ? {} : { search: query.search }),
        first: (query.page - 1) * query.pageSize,
        max: query.pageSize,
      }),
    );
    const data = await mapConcurrent(page.users, ROLE_LOOKUP_CONCURRENCY, async (user) =>
      toSummary(user, await withIdpErrors(() => this.idp.getEffectiveRoles(user.id))),
    );
    return { data, meta: buildPaginationMeta(query, page.total) };
  }

  async get(userId: string): Promise<UserSummary> {
    const user = await this.requireUser(userId);
    return toSummary(user, await withIdpErrors(() => this.idp.getEffectiveRoles(userId)));
  }

  async setRoles(
    context: ActorContext,
    userId: string,
    request: UpdateUserRolesRequest,
  ): Promise<UserSummary> {
    const actor = context.principal;
    if (actor.subject === userId) {
      throw new ForbiddenException('You cannot change your own roles');
    }
    const user = await this.requireUser(userId);
    await this.assertMayManage(actor, userId);

    const current = await withIdpErrors(() => this.idp.getDirectRoles(userId));
    const target = ROLES.filter((role) => request.roles.includes(role));
    const added = target.filter((role) => !current.includes(role));
    const removed = current.filter((role) => !target.includes(role));
    const forbidden = [...added, ...removed].filter(
      (role) => !canAssignRole(actor.permissions, role),
    );
    if (forbidden.length > 0) {
      await this.audit.record(context, {
        action: 'identity.user.roles-changed',
        outcome: 'denied',
        resourceType: 'user',
        resourceId: userId,
        details: { requested: target, forbidden },
      });
      throw new ForbiddenException(`You may not grant or revoke: ${forbidden.join(', ')}`);
    }
    if (removed.includes('super-admin')) await this.assertNotLastSuperAdmin(userId);

    if (added.length > 0 || removed.length > 0) {
      await withIdpErrors(() => this.idp.addRoles(userId, added));
      await withIdpErrors(() => this.idp.removeRoles(userId, removed));
      await this.audit.record(context, {
        action: 'identity.user.roles-changed',
        resourceType: 'user',
        resourceId: userId,
        details: {
          previousRoles: current,
          roles: target,
          added,
          removed,
          ...(request.reason === undefined ? {} : { reason: request.reason }),
        },
        events: [
          {
            eventType: IDENTITY_EVENT_TYPES.userRolesChanged,
            payload: { userId, previousRoles: current, roles: target, changedBy: actor.subject },
          },
        ],
      });
      // Access tokens carry roles; revoking sessions makes a demotion effective immediately.
      if (removed.length > 0) await this.sessions.revokeAll(context, userId, 'roles-changed');
    }
    return toSummary(user, await withIdpErrors(() => this.idp.getEffectiveRoles(userId)));
  }

  async setStatus(
    context: ActorContext,
    userId: string,
    request: UpdateUserStatusRequest,
  ): Promise<UserSummary> {
    const actor = context.principal;
    if (actor.subject === userId) {
      throw new ForbiddenException('You cannot change your own account status');
    }
    const user = await this.requireUser(userId);
    await this.assertMayManage(actor, userId);
    if (!request.enabled) {
      const roles = await withIdpErrors(() => this.idp.getDirectRoles(userId));
      if (roles.includes('super-admin')) await this.assertNotLastSuperAdmin(userId);
    }
    if (user.enabled !== request.enabled) {
      await withIdpErrors(() => this.idp.updateUser(userId, { enabled: request.enabled }));
      await this.audit.record(context, {
        action: request.enabled ? 'identity.user.enabled' : 'identity.user.disabled',
        resourceType: 'user',
        resourceId: userId,
        details: request.reason === undefined ? {} : { reason: request.reason },
        events: [
          {
            eventType: IDENTITY_EVENT_TYPES.userStatusChanged,
            payload: { userId, enabled: request.enabled, changedBy: actor.subject },
          },
        ],
      });
      if (!request.enabled) await this.sessions.revokeAll(context, userId, 'user-disabled');
    }
    return this.get(userId);
  }

  /**
   * Forces a password change at the next login (Keycloak required action) and ends the user's
   * sessions. The new password is chosen by the user on Keycloak's own page.
   */
  async requirePasswordUpdate(context: ActorContext, userId: string): Promise<UserSummary> {
    const actor = context.principal;
    if (actor.subject === userId) {
      throw new BadRequestException('Use the credential actions of your own profile instead');
    }
    const user = await this.requireUser(userId);
    await this.assertMayManage(actor, userId);
    if (!user.requiredActions.includes(UPDATE_PASSWORD_ACTION)) {
      await withIdpErrors(() =>
        this.idp.updateUser(userId, {
          requiredActions: [...user.requiredActions, UPDATE_PASSWORD_ACTION],
        }),
      );
    }
    await this.audit.record(context, {
      action: 'identity.user.password-update-required',
      resourceType: 'user',
      resourceId: userId,
    });
    await this.sessions.revokeAll(context, userId, 'admin-revoked');
    return this.get(userId);
  }

  /** Session administration of another user (same delegation rules). */
  async assertMayManageSessions(actor: AuthenticatedPrincipal, userId: string): Promise<void> {
    await this.requireUser(userId);
    await this.assertMayManage(actor, userId);
  }

  private async requireUser(userId: string): Promise<IdpUser> {
    const user = await withIdpErrors(() => this.idp.getUser(userId));
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  /** Only holders of `role:assign-privileged` may act on Administrators and Super Admins. */
  private async assertMayManage(actor: AuthenticatedPrincipal, userId: string): Promise<void> {
    if (actor.permissions.includes('role:assign-privileged')) return;
    const roles = await withIdpErrors(() => this.idp.getEffectiveRoles(userId));
    if (roles.some((role) => PRIVILEGED_ROLES.includes(role))) {
      throw new ForbiddenException('Only a Super Admin can manage privileged accounts');
    }
  }

  private async assertNotLastSuperAdmin(userId: string): Promise<void> {
    const holders = await withIdpErrors(() => this.idp.listEnabledUsersWithRole('super-admin'));
    if (holders.every((holder) => holder.id === userId)) {
      throw new ConflictException('The last enabled Super Admin cannot be demoted or disabled');
    }
  }
}
