import type { Request } from 'express';

import type { Permission, Role } from '@cve/contracts';
import type { Logger } from '@cve/logger';

import type { AuthFailureReason } from '../errors.js';
import type { AuthenticatedPrincipal } from '../principal.js';
import type { SessionChecker } from '../session-checker.js';
import type { TokenVerifier } from '../token-verifier.js';

export interface AccessDeniedEvent {
  readonly request: Request;
  readonly principal: AuthenticatedPrincipal;
  readonly missingPermissions: readonly Permission[];
  readonly requiredRoles: readonly Role[];
}

export interface AuthenticationFailedEvent {
  readonly request: Request;
  readonly reason: AuthFailureReason;
}

/** Hooks for audit logging; failures inside a hook are logged and never change the response. */
export interface AuthEventListener {
  onAuthenticationFailed?(event: AuthenticationFailedEvent): void | Promise<void>;
  onAccessDenied?(event: AccessDeniedEvent): void | Promise<void>;
}

export interface AuthModuleOptions {
  readonly verifier: TokenVerifier;
  /** Optional session liveness check (token introspection), applied after local validation. */
  readonly sessionChecker?: SessionChecker;
  readonly logger: Logger;
  readonly listener?: AuthEventListener;
}
