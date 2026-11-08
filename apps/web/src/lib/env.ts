import 'server-only';

import { z } from 'zod';

const httpUrl = (name: string) =>
  z
    .url()
    .refine((value) => ['http:', 'https:'].includes(new URL(value).protocol), {
      message: `${name} must be an http(s) URL`,
    })
    .transform((value) => value.replace(/\/+$/, ''));

/**
 * Server-side configuration. Nothing here is exposed to the browser: the web server talks to
 * Keycloak and the API Gateway on behalf of the browser (backend-for-frontend), so access and
 * refresh tokens never reach client-side JavaScript.
 */
export const serverEnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    API_GATEWAY_INTERNAL_URL: httpUrl('API_GATEWAY_INTERNAL_URL').default('http://localhost:4000'),
    /** Origin users open in the browser (Nginx); defines the OIDC redirect URI and CSRF checks. */
    PUBLIC_ORIGIN: httpUrl('PUBLIC_ORIGIN')
      .refine((value) => new URL(value).pathname === '/', {
        message: 'PUBLIC_ORIGIN must be an origin without a path',
      })
      .default('http://localhost:3000'),
    /** Keycloak base URL as browsers reach it (authorization endpoint, issuer). */
    KEYCLOAK_PUBLIC_URL: httpUrl('KEYCLOAK_PUBLIC_URL').default('http://localhost:8180/auth'),
    /** Keycloak base URL reachable from the web server (token endpoint). Defaults to the public URL. */
    KEYCLOAK_URL: httpUrl('KEYCLOAK_URL').optional(),
    KEYCLOAK_REALM: z
      .string()
      .regex(/^[A-Za-z0-9_-]{1,64}$/)
      .default('cve-platform'),
    KEYCLOAK_WEB_CLIENT_ID: z
      .string()
      .regex(/^[A-Za-z0-9_-]{1,64}$/)
      .default('cve-web'),
    KEYCLOAK_TIMEOUT_MS: z.coerce.number().int().min(500).max(60_000).default(5_000),
    /** Encrypts the session cookie (AES-256-GCM, key derived with HKDF). At least 32 characters. */
    WEB_SESSION_SECRET: z.string().min(32, {
      message: 'WEB_SESSION_SECRET must be at least 32 characters',
    }),
    /** Gateway request timeout for proxied API calls. */
    API_PROXY_TIMEOUT_MS: z.coerce.number().int().min(1_000).max(120_000).default(20_000),
  })
  .transform((env) => ({ ...env, KEYCLOAK_URL: env.KEYCLOAK_URL ?? env.KEYCLOAK_PUBLIC_URL }));

export type ServerEnv = z.output<typeof serverEnvSchema>;

export function parseServerEnv(source: Readonly<Record<string, string | undefined>>): ServerEnv {
  const cleaned = Object.fromEntries(
    Object.entries(source).filter(([, value]) => value !== undefined && value !== ''),
  );
  const result = serverEnvSchema.safeParse(cleaned);
  if (!result.success) {
    // Error messages name the variable, never its value.
    const problems = result.error.issues
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join('; ');
    throw new Error(`Invalid web server configuration: ${problems}`);
  }
  return result.data;
}

let cached: ServerEnv | undefined;

export function getServerEnv(): ServerEnv {
  cached ??= parseServerEnv(process.env);
  return cached;
}

/** Only the gateway address, for code paths that work without a session (health). */
export function getGatewayUrl(): string {
  const parsed = httpUrl('API_GATEWAY_INTERNAL_URL')
    .default('http://localhost:4000')
    .safeParse(process.env['API_GATEWAY_INTERNAL_URL'] === '' ? undefined : process.env['API_GATEWAY_INTERNAL_URL']);
  if (!parsed.success) throw new Error('Invalid web server configuration: API_GATEWAY_INTERNAL_URL');
  return parsed.data;
}
