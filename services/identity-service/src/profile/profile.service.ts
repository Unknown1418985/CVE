import { Inject, Injectable } from '@nestjs/common';

import type { AuthenticatedPrincipal } from '@cve/auth';
import { keycloakRealmUrls } from '@cve/auth';
import {
  CREDENTIAL_ACTIONS,
  type CredentialAction,
  type CredentialActionLink,
  type UpdateProfileRequest,
  type UserProfile,
} from '@cve/contracts';

import { AuditService } from '../audit/audit.service.js';
import { withIdpErrors } from '../common/errors.js';
import type { ActorContext } from '../common/request-context.js';
import { IDENTITY_PROVIDER, type IdentityProvider } from '../keycloak/identity-provider.js';
import {
  PROFILE_REPOSITORY,
  type ProfileRepository,
  type StoredProfile,
} from '../persistence/ports.js';
import { IDENTITY_OPTIONS, type IdentityOptions } from '../identity.options.js';

/** Keycloak required-action aliases behind each credential action. */
const KC_ACTIONS: Readonly<Record<CredentialAction, string>> = {
  'update-password': 'UPDATE_PASSWORD',
  'configure-totp': 'CONFIGURE_TOTP',
};

@Injectable()
export class ProfileService {
  constructor(
    @Inject(PROFILE_REPOSITORY) private readonly profiles: ProfileRepository,
    @Inject(IDENTITY_PROVIDER) private readonly idp: IdentityProvider,
    @Inject(IDENTITY_OPTIONS) private readonly options: IdentityOptions,
    private readonly audit: AuditService,
  ) {}

  private view(
    principal: AuthenticatedPrincipal,
    stored: StoredProfile,
    names: { firstName: string | null; lastName: string | null } = {
      firstName: principal.givenName ?? null,
      lastName: principal.familyName ?? null,
    },
  ): UserProfile {
    return {
      id: principal.subject,
      username: principal.username,
      email: principal.email ?? null,
      emailVerified: principal.emailVerified,
      firstName: names.firstName,
      lastName: names.lastName,
      displayName: stored.displayName,
      jobTitle: stored.jobTitle,
      timezone: stored.timezone,
      roles: [...principal.roles],
      permissions: [...principal.permissions],
      firstSeenAt: stored.firstSeenAt.toISOString(),
      lastSeenAt: stored.lastSeenAt.toISOString(),
    };
  }

  private touch(principal: AuthenticatedPrincipal): Promise<StoredProfile> {
    return this.profiles.touch(
      { id: principal.subject, username: principal.username, email: principal.email ?? null },
      new Date(),
    );
  }

  /** Profile of the caller; roles and permissions come from the validated token. */
  async me(principal: AuthenticatedPrincipal): Promise<UserProfile> {
    return this.view(principal, await this.touch(principal));
  }

  async update(context: ActorContext, request: UpdateProfileRequest): Promise<UserProfile> {
    const { principal } = context;
    await this.touch(principal);
    const names = {
      firstName: request.firstName ?? principal.givenName ?? null,
      lastName: request.lastName ?? principal.familyName ?? null,
    };
    if (request.firstName !== undefined || request.lastName !== undefined) {
      await withIdpErrors(() =>
        this.idp.updateUser(principal.subject, {
          ...(request.firstName === undefined ? {} : { firstName: request.firstName }),
          ...(request.lastName === undefined ? {} : { lastName: request.lastName }),
        }),
      );
    }
    const stored = await this.profiles.update(principal.subject, {
      ...(request.displayName === undefined ? {} : { displayName: request.displayName }),
      ...(request.jobTitle === undefined ? {} : { jobTitle: request.jobTitle }),
      ...(request.timezone === undefined ? {} : { timezone: request.timezone }),
    });
    await this.audit.record(context, {
      action: 'identity.profile.updated',
      resourceType: 'user',
      resourceId: principal.subject,
      details: { fields: Object.keys(request).sort() },
    });
    return this.view(principal, stored, names);
  }

  /**
   * Links that start Keycloak application-initiated actions. Passwords and second factors are
   * entered on Keycloak's own pages; they never pass through the platform.
   */
  credentialActions(): CredentialActionLink[] {
    const urls = keycloakRealmUrls(this.options.keycloakPublicUrl, this.options.realm);
    return CREDENTIAL_ACTIONS.map((action) => {
      const url = new URL(urls.authorization);
      url.searchParams.set('client_id', this.options.webClientId);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', 'openid');
      url.searchParams.set('redirect_uri', this.options.accountRedirectUri);
      url.searchParams.set('kc_action', KC_ACTIONS[action]);
      return { action, url: url.toString() };
    });
  }
}
