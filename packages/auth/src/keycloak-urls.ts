/** Endpoints of one Keycloak realm, built from a base URL such as `http://keycloak:8180/auth`. */
export interface KeycloakRealmUrls {
  readonly issuer: string;
  readonly jwks: string;
  readonly introspection: string;
  readonly token: string;
  readonly authorization: string;
  readonly endSession: string;
  /** Admin REST API root for the realm. */
  readonly admin: string;
}

const REALM_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

export function keycloakRealmUrls(baseUrl: string, realm: string): KeycloakRealmUrls {
  if (!REALM_PATTERN.test(realm)) throw new Error(`Invalid Keycloak realm name "${realm}"`);
  const base = baseUrl.replace(/\/+$/, '');
  const realmUrl = `${base}/realms/${realm}`;
  const oidc = `${realmUrl}/protocol/openid-connect`;
  return {
    issuer: realmUrl,
    jwks: `${oidc}/certs`,
    introspection: `${oidc}/token/introspect`,
    token: `${oidc}/token`,
    authorization: `${oidc}/auth`,
    endSession: `${oidc}/logout`,
    admin: `${base}/admin/realms/${realm}`,
  };
}
