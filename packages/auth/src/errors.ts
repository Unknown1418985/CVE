/** Why a bearer token was rejected. Never contains token material. */
export type AuthFailureReason =
  | 'missing-token'
  | 'malformed-header'
  | 'invalid-token'
  | 'expired-token'
  | 'wrong-issuer'
  | 'wrong-audience'
  | 'wrong-token-type'
  | 'session-inactive';

export class AuthenticationError extends Error {
  constructor(
    readonly reason: AuthFailureReason,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'AuthenticationError';
  }
}

/** The identity provider could not be reached to validate a token; callers fail closed. */
export class IdentityProviderUnavailableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'IdentityProviderUnavailableError';
  }
}
