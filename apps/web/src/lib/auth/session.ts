import 'server-only';

import { z } from 'zod';

import type { ServerEnv } from '@/lib/env';

import { OidcError, readClaims, refreshTokenSet, type TokenSet } from './oidc';
import { deriveKey, seal, unseal } from './seal';

export const SESSION_COOKIE = 'cve_session';
export const TRANSACTION_COOKIE = 'cve_oidc_tx';
const SESSION_PURPOSE = 'session.v1';
const TRANSACTION_PURPOSE = 'oidc-transaction.v1';
/** Browsers accept about 4 KiB per cookie including attributes; stay well below. */
const CHUNK_SIZE = 3_500;
const MAX_CHUNKS = 4;
/** Refresh this long before the access token expires. */
const REFRESH_MARGIN_MS = 30_000;
const TRANSACTION_TTL_MS = 10 * 60_000;

export interface CookieReader {
  get(name: string): { value: string } | undefined;
}

export interface CookieOptions {
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'lax' | 'strict';
  path: string;
  maxAge?: number;
}

export interface CookieWriter {
  set(name: string, value: string, options: CookieOptions): unknown;
}

const sessionSchema = z.object({
  accessToken: z.string().min(1),
  refreshToken: z.string().min(1),
  accessExpiresAt: z.number(),
  refreshExpiresAt: z.number().nullable(),
  subject: z.string().min(1),
  username: z.string().nullable(),
});
export type Session = z.infer<typeof sessionSchema>;

const transactionSchema = z.object({
  state: z.string().min(16),
  nonce: z.string().min(16),
  codeVerifier: z.string().min(43),
  returnTo: z.string(),
  createdAt: z.number(),
});
export type OidcTransaction = z.infer<typeof transactionSchema>;

function cookieOptions(env: ServerEnv, maxAge?: number): CookieOptions {
  return {
    httpOnly: true,
    secure: env.PUBLIC_ORIGIN.startsWith('https:'),
    // `lax` so that the session survives top-level navigations from links; state-changing BFF
    // calls are additionally protected by an Origin check and a custom header.
    sameSite: 'lax',
    path: '/',
    ...(maxAge === undefined ? {} : { maxAge }),
  };
}

export function sessionFromTokens(tokens: TokenSet): Session | null {
  const claims = readClaims(tokens.accessToken);
  if (claims === null) return null;
  return {
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    accessExpiresAt: tokens.accessExpiresAt,
    refreshExpiresAt: tokens.refreshExpiresAt,
    subject: claims.sub,
    username: claims.preferred_username ?? null,
  };
}

export function readSession(
  env: ServerEnv,
  cookies: CookieReader,
  now = Date.now(),
): Session | null {
  const parts: string[] = [];
  for (let index = 0; index < MAX_CHUNKS; index += 1) {
    const value = cookies.get(index === 0 ? SESSION_COOKIE : `${SESSION_COOKIE}.${index}`)?.value;
    if (value === undefined || value === '') break;
    parts.push(value);
  }
  if (parts.length === 0) return null;
  const raw = unseal(
    parts.join(''),
    deriveKey(env.WEB_SESSION_SECRET, SESSION_PURPOSE),
    SESSION_PURPOSE,
  );
  const parsed = sessionSchema.safeParse(raw);
  if (!parsed.success) return null;
  if (parsed.data.refreshExpiresAt !== null && parsed.data.refreshExpiresAt <= now) return null;
  return parsed.data;
}

export function writeSession(env: ServerEnv, cookies: CookieWriter, session: Session): void {
  const sealed = seal(session, deriveKey(env.WEB_SESSION_SECRET, SESSION_PURPOSE), SESSION_PURPOSE);
  const chunks: string[] = [];
  for (let offset = 0; offset < sealed.length; offset += CHUNK_SIZE) {
    chunks.push(sealed.slice(offset, offset + CHUNK_SIZE));
  }
  if (chunks.length > MAX_CHUNKS) throw new Error('Session is too large for cookies');
  const maxAge =
    session.refreshExpiresAt === null
      ? undefined
      : Math.max(1, Math.floor((session.refreshExpiresAt - Date.now()) / 1000));
  for (let index = 0; index < MAX_CHUNKS; index += 1) {
    const name = index === 0 ? SESSION_COOKIE : `${SESSION_COOKIE}.${index}`;
    const chunk = chunks[index];
    if (chunk === undefined) {
      cookies.set(name, '', cookieOptions(env, 0));
    } else {
      cookies.set(name, chunk, cookieOptions(env, maxAge));
    }
  }
}

export function clearSession(env: ServerEnv, cookies: CookieWriter): void {
  for (let index = 0; index < MAX_CHUNKS; index += 1) {
    cookies.set(
      index === 0 ? SESSION_COOKIE : `${SESSION_COOKIE}.${index}`,
      '',
      cookieOptions(env, 0),
    );
  }
}

export function writeTransaction(env: ServerEnv, cookies: CookieWriter, tx: OidcTransaction): void {
  cookies.set(
    TRANSACTION_COOKIE,
    seal(tx, deriveKey(env.WEB_SESSION_SECRET, TRANSACTION_PURPOSE), TRANSACTION_PURPOSE),
    cookieOptions(env, Math.floor(TRANSACTION_TTL_MS / 1000)),
  );
}

export function readTransaction(
  env: ServerEnv,
  cookies: CookieReader,
  now = Date.now(),
): OidcTransaction | null {
  const value = cookies.get(TRANSACTION_COOKIE)?.value;
  if (value === undefined || value === '') return null;
  const parsed = transactionSchema.safeParse(
    unseal(value, deriveKey(env.WEB_SESSION_SECRET, TRANSACTION_PURPOSE), TRANSACTION_PURPOSE),
  );
  if (!parsed.success || now - parsed.data.createdAt > TRANSACTION_TTL_MS) return null;
  return parsed.data;
}

export function clearTransaction(env: ServerEnv, cookies: CookieWriter): void {
  cookies.set(TRANSACTION_COOKIE, '', cookieOptions(env, 0));
}

export function needsRefresh(session: Session, now = Date.now()): boolean {
  return session.accessExpiresAt - REFRESH_MARGIN_MS <= now;
}

/**
 * Keycloak rotates refresh tokens and rejects reuse (`revokeRefreshToken`), so concurrent
 * requests of one browser must share a single refresh. Results are kept briefly for requests
 * that still carry the old cookie.
 */
const inflight = new Map<string, Promise<Session | null>>();
const SHARE_REFRESH_MS = 15_000;

export type RefreshOutcome =
  | { readonly kind: 'refreshed'; readonly session: Session }
  | { readonly kind: 'expired' }
  | { readonly kind: 'unavailable' };

export async function refreshSession(
  env: ServerEnv,
  session: Session,
  fetchFn: typeof fetch = fetch,
): Promise<RefreshOutcome> {
  let pending = inflight.get(session.refreshToken);
  if (pending === undefined) {
    pending = refreshTokenSet(env, session.refreshToken, fetchFn).then((tokens) =>
      sessionFromTokens(tokens),
    );
    inflight.set(session.refreshToken, pending);
    const key = session.refreshToken;
    pending.then(
      () => setTimeout(() => inflight.delete(key), SHARE_REFRESH_MS).unref(),
      () => inflight.delete(key),
    );
  }
  try {
    const next = await pending;
    return next === null ? { kind: 'expired' } : { kind: 'refreshed', session: next };
  } catch (error) {
    if (error instanceof OidcError && error.invalidGrant) return { kind: 'expired' };
    return { kind: 'unavailable' };
  }
}
