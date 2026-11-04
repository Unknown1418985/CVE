export interface IdentityOptions {
  readonly realm: string;
  readonly keycloakPublicUrl: string;
  readonly webClientId: string;
  readonly accountRedirectUri: string;
}

export const IDENTITY_OPTIONS = Symbol('IDENTITY_OPTIONS');
