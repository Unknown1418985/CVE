import { Inject, Injectable, NotFoundException } from '@nestjs/common';

import { IDENTITY_EVENT_TYPES, type UserSession } from '@cve/contracts';

import { AuditService } from '../audit/audit.service.js';
import { withIdpErrors } from '../common/errors.js';
import type { ActorContext } from '../common/request-context.js';
import {
  IDENTITY_PROVIDER,
  type IdentityProvider,
  type IdpSession,
} from '../keycloak/identity-provider.js';

type RevocationReason =
  'logout' | 'user-revoked' | 'admin-revoked' | 'roles-changed' | 'user-disabled';

function toView(session: IdpSession, currentSessionId: string | undefined): UserSession {
  return {
    id: session.id,
    ipAddress: session.ipAddress,
    startedAt: session.startedAt.toISOString(),
    lastAccessAt: session.lastAccessAt.toISOString(),
    clients: [...session.clients],
    current: session.id === currentSessionId,
  };
}

/** Keycloak SSO sessions. Deleting a session also invalidates its refresh tokens. */
@Injectable()
export class SessionsService {
  constructor(
    @Inject(IDENTITY_PROVIDER) private readonly idp: IdentityProvider,
    private readonly audit: AuditService,
  ) {}

  async list(userId: string, currentSessionId?: string): Promise<UserSession[]> {
    const sessions = await withIdpErrors(() => this.idp.listSessions(userId));
    return sessions
      .sort((a, b) => b.lastAccessAt.getTime() - a.lastAccessAt.getTime())
      .map((session) => toView(session, currentSessionId));
  }

  /** Revokes one session after verifying that it belongs to `userId`. */
  async revoke(
    context: ActorContext,
    userId: string,
    sessionId: string,
    reason: RevocationReason,
  ): Promise<void> {
    const sessions = await withIdpErrors(() => this.idp.listSessions(userId));
    if (!sessions.some((session) => session.id === sessionId)) {
      throw new NotFoundException('Session not found');
    }
    await withIdpErrors(() => this.idp.deleteSession(sessionId));
    await this.recordRevocation(context, userId, reason, sessionId);
  }

  /** Revokes every session of `userId`. Returns how many were active. */
  async revokeAll(
    context: ActorContext,
    userId: string,
    reason: RevocationReason,
  ): Promise<number> {
    const sessions = await withIdpErrors(() => this.idp.listSessions(userId));
    await withIdpErrors(() => this.idp.logoutUser(userId));
    await this.recordRevocation(context, userId, reason, undefined, sessions.length);
    return sessions.length;
  }

  /** Secure logout: ends the caller's current Keycloak session (or all of them). */
  async logout(context: ActorContext, allSessions: boolean): Promise<number> {
    const { principal } = context;
    if (allSessions || principal.sessionId === undefined) {
      return this.revokeAll(context, principal.subject, 'logout');
    }
    const sessionId = principal.sessionId;
    // The session may already be gone (expired or revoked elsewhere): logout stays idempotent.
    const sessions = await withIdpErrors(() => this.idp.listSessions(principal.subject));
    if (sessions.some((session) => session.id === sessionId)) {
      await withIdpErrors(() => this.idp.deleteSession(sessionId));
    }
    await this.recordRevocation(context, principal.subject, 'logout', sessionId);
    return sessions.some((session) => session.id === sessionId) ? 1 : 0;
  }

  private async recordRevocation(
    context: ActorContext,
    userId: string,
    reason: RevocationReason,
    sessionId?: string,
    count?: number,
  ): Promise<void> {
    await this.audit.record(context, {
      action: reason === 'logout' ? 'identity.session.logged-out' : 'identity.session.revoked',
      resourceType: 'user',
      resourceId: userId,
      details: {
        reason,
        ...(sessionId === undefined ? { scope: 'all' } : { sessionId }),
        ...(count === undefined ? {} : { sessions: count }),
      },
      events: [
        {
          eventType: IDENTITY_EVENT_TYPES.sessionRevoked,
          payload: {
            userId,
            ...(sessionId === undefined ? {} : { sessionId }),
            revokedBy: context.principal.subject,
            reason,
          },
        },
      ],
    });
  }
}
