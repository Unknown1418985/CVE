import { createHash } from 'node:crypto';

import { z } from 'zod';

import { keycloakRealmUrls, platformRoles } from '@cve/auth';
import type { Role } from '@cve/contracts';
import type { Logger } from '@cve/logger';

import {
  IdentityProviderError,
  type IdentityProvider,
  type IdpEvent,
  type IdpSession,
  type IdpUser,
  type UserPage,
  type UserUpdate,
} from './identity-provider.js';

export interface KeycloakAdminClientOptions {
  /** Internal base URL, e.g. `http://keycloak:8180/auth`. */
  readonly baseUrl: string;
  readonly realm: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly timeoutMs: number;
  readonly logger: Logger;
  readonly fetch?: typeof fetch;
}

const tokenResponseSchema = z.object({
  access_token: z.string().min(1),
  expires_in: z.number().int().positive(),
});

const userSchema = z.object({
  id: z.string(),
  username: z.string(),
  email: z.string().optional(),
  firstName: z.string().optional(),
  lastName: z.string().optional(),
  enabled: z.boolean().optional(),
  emailVerified: z.boolean().optional(),
  createdTimestamp: z.number().optional(),
  requiredActions: z.array(z.string()).optional(),
});

const roleSchema = z.object({ id: z.string(), name: z.string() });

const sessionSchema = z.object({
  id: z.string(),
  userId: z.string(),
  ipAddress: z.string().optional(),
  start: z.number(),
  lastAccess: z.number(),
  clients: z.record(z.string(), z.string()).optional(),
});

const eventSchema = z.object({
  id: z.string().optional(),
  time: z.number(),
  type: z.string(),
  clientId: z.string().nullish(),
  userId: z.string().nullish(),
  sessionId: z.string().nullish(),
  ipAddress: z.string().nullish(),
  error: z.string().nullish(),
  details: z.record(z.string(), z.string()).nullish(),
});

const adminEventSchema = z.object({
  id: z.string().optional(),
  time: z.number(),
  operationType: z.string(),
  resourceType: z.string().nullish(),
  resourcePath: z.string().nullish(),
  error: z.string().nullish(),
  authDetails: z
    .object({
      userId: z.string().nullish(),
      clientId: z.string().nullish(),
      ipAddress: z.string().nullish(),
    })
    .nullish(),
});

const USER_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SESSION_ID_PATTERN = /^[A-Za-z0-9-]{8,64}$/;
const PAGE_SIZE = 100;
const MAX_PAGES = 50;

function assertUserId(userId: string): string {
  if (!USER_ID_PATTERN.test(userId)) throw new IdentityProviderError('Invalid user ID', 400);
  return encodeURIComponent(userId);
}

function toUser(raw: z.infer<typeof userSchema>): IdpUser {
  return {
    id: raw.id,
    username: raw.username,
    email: raw.email ?? null,
    firstName: raw.firstName ?? null,
    lastName: raw.lastName ?? null,
    enabled: raw.enabled ?? false,
    emailVerified: raw.emailVerified ?? false,
    createdAt: raw.createdTimestamp === undefined ? null : new Date(raw.createdTimestamp),
    requiredActions: raw.requiredActions ?? [],
  };
}

function contentId(parts: readonly (string | number | null | undefined)[]): string {
  return createHash('sha256')
    .update(parts.map((part) => String(part ?? '')).join('\u001f'))
    .digest('hex')
    .slice(0, 64);
}

/**
 * Keycloak Admin REST API client authenticated with the Identity Service's service account
 * (client credentials). The account holds only `view-users`, `query-users`, `manage-users`,
 * `view-realm` and `view-events` on `realm-management`.
 */
export class KeycloakAdminClient implements IdentityProvider {
  private readonly urls;
  private readonly fetchFn: typeof fetch;
  private token: { value: string; expiresAt: number } | undefined;
  private tokenRequest: Promise<string> | undefined;
  private readonly roleIds = new Map<Role, { id: string; name: string }>();

  constructor(private readonly options: KeycloakAdminClientOptions) {
    this.urls = keycloakRealmUrls(options.baseUrl, options.realm);
    this.fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  // ------------------------------------------------------------------ transport

  private async accessToken(): Promise<string> {
    if (this.token && this.token.expiresAt > Date.now()) return this.token.value;
    this.tokenRequest ??= this.requestToken().finally(() => {
      this.tokenRequest = undefined;
    });
    return this.tokenRequest;
  }

  private async requestToken(): Promise<string> {
    const response = await this.send(this.urls.token, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.options.clientId,
        client_secret: this.options.clientSecret,
      }).toString(),
    });
    if (!response.ok) {
      throw new IdentityProviderError(
        `Keycloak service-account login failed (HTTP ${response.status})`,
        502,
      );
    }
    const parsed = tokenResponseSchema.safeParse(await response.json().catch(() => null));
    if (!parsed.success) {
      throw new IdentityProviderError('Keycloak returned an invalid token response', 502);
    }
    // Refresh 30 s before expiry.
    const lifetimeMs = Math.max(parsed.data.expires_in - 30, 5) * 1000;
    this.token = { value: parsed.data.access_token, expiresAt: Date.now() + lifetimeMs };
    return parsed.data.access_token;
  }

  private async send(url: string, init: RequestInit, timeoutMs = this.options.timeoutMs) {
    try {
      return await this.fetchFn(url, {
        ...init,
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      throw new IdentityProviderError('Keycloak is unreachable', 503, { cause: error });
    }
  }

  private async admin(
    method: string,
    path: string,
    options: { body?: unknown; allowNotFound?: boolean } = {},
  ): Promise<unknown> {
    const call = async () =>
      this.send(`${this.urls.admin}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${await this.accessToken()}`,
          accept: 'application/json',
          ...(options.body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
      });
    let response = await call();
    if (response.status === 401) {
      // The cached service-account token may have been revoked; retry once with a new one.
      this.token = undefined;
      response = await call();
    }
    if (response.status === 404 && options.allowNotFound === true) return null;
    if (!response.ok) {
      this.options.logger.warn(
        { method, path: path.replace(USER_ID_PATTERN, ':id'), status: response.status },
        'keycloak admin request failed',
      );
      throw new IdentityProviderError(
        `Keycloak admin request failed (HTTP ${response.status})`,
        response.status === 404 ? 404 : response.status === 409 ? 409 : 502,
      );
    }
    if (response.status === 204) return undefined;
    const text = await response.text();
    if (text.length === 0) return undefined;
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new IdentityProviderError('Keycloak returned invalid JSON', 502);
    }
  }

  private parse<T extends z.ZodType>(schema: T, value: unknown): z.infer<T> {
    const parsed = schema.safeParse(value);
    if (!parsed.success) {
      throw new IdentityProviderError('Keycloak returned an unexpected response', 502);
    }
    return parsed.data;
  }

  private async roleRepresentations(roles: readonly Role[]) {
    const result: { id: string; name: string }[] = [];
    for (const role of roles) {
      let representation = this.roleIds.get(role);
      if (!representation) {
        representation = this.parse(
          roleSchema,
          await this.admin('GET', `/roles/${encodeURIComponent(role)}`),
        );
        this.roleIds.set(role, representation);
      }
      result.push(representation);
    }
    return result;
  }

  // ------------------------------------------------------------------ users

  async listUsers(query: { search?: string; first: number; max: number }): Promise<UserPage> {
    const params = new URLSearchParams({
      first: String(query.first),
      max: String(query.max),
      briefRepresentation: 'false',
    });
    const countParams = new URLSearchParams();
    if (query.search !== undefined) {
      params.set('search', query.search);
      countParams.set('search', query.search);
    }
    const [users, total] = await Promise.all([
      this.admin('GET', `/users?${params.toString()}`),
      this.admin('GET', `/users/count?${countParams.toString()}`),
    ]);
    return {
      users: this.parse(z.array(userSchema), users).map(toUser),
      total: this.parse(z.number().int().min(0), total),
    };
  }

  async getUser(userId: string): Promise<IdpUser | null> {
    const raw = await this.admin('GET', `/users/${assertUserId(userId)}`, { allowNotFound: true });
    return raw === null ? null : toUser(this.parse(userSchema, raw));
  }

  async updateUser(userId: string, update: UserUpdate): Promise<void> {
    await this.admin('PUT', `/users/${assertUserId(userId)}`, {
      body: {
        ...(update.firstName === undefined ? {} : { firstName: update.firstName }),
        ...(update.lastName === undefined ? {} : { lastName: update.lastName }),
        ...(update.enabled === undefined ? {} : { enabled: update.enabled }),
        ...(update.requiredActions === undefined
          ? {}
          : { requiredActions: [...update.requiredActions] }),
      },
    });
  }

  async getDirectRoles(userId: string): Promise<Role[]> {
    const raw = await this.admin('GET', `/users/${assertUserId(userId)}/role-mappings/realm`);
    return platformRoles(this.parse(z.array(roleSchema), raw).map((role) => role.name));
  }

  async getEffectiveRoles(userId: string): Promise<Role[]> {
    const raw = await this.admin(
      'GET',
      `/users/${assertUserId(userId)}/role-mappings/realm/composite`,
    );
    return platformRoles(this.parse(z.array(roleSchema), raw).map((role) => role.name));
  }

  async addRoles(userId: string, roles: readonly Role[]): Promise<void> {
    if (roles.length === 0) return;
    await this.admin('POST', `/users/${assertUserId(userId)}/role-mappings/realm`, {
      body: await this.roleRepresentations(roles),
    });
  }

  async removeRoles(userId: string, roles: readonly Role[]): Promise<void> {
    if (roles.length === 0) return;
    await this.admin('DELETE', `/users/${assertUserId(userId)}/role-mappings/realm`, {
      body: await this.roleRepresentations(roles),
    });
  }

  async listEnabledUsersWithRole(role: Role): Promise<IdpUser[]> {
    const users: IdpUser[] = [];
    for (let page = 0; page < MAX_PAGES; page += 1) {
      const raw = await this.admin(
        'GET',
        `/roles/${encodeURIComponent(role)}/users?first=${page * PAGE_SIZE}&max=${PAGE_SIZE}&briefRepresentation=false`,
      );
      const batch = this.parse(z.array(userSchema), raw).map(toUser);
      users.push(...batch.filter((user) => user.enabled));
      if (batch.length < PAGE_SIZE) return users;
    }
    throw new IdentityProviderError(`Too many users hold role ${role}`, 502);
  }

  // ------------------------------------------------------------------ sessions

  async listSessions(userId: string): Promise<IdpSession[]> {
    const raw = await this.admin('GET', `/users/${assertUserId(userId)}/sessions`);
    return this.parse(z.array(sessionSchema), raw).map((session) => ({
      id: session.id,
      userId: session.userId,
      ipAddress: session.ipAddress ?? null,
      startedAt: new Date(session.start),
      lastAccessAt: new Date(session.lastAccess),
      clients: Object.values(session.clients ?? {}),
    }));
  }

  async deleteSession(sessionId: string): Promise<void> {
    if (!SESSION_ID_PATTERN.test(sessionId)) {
      throw new IdentityProviderError('Invalid session ID', 400);
    }
    await this.admin('DELETE', `/sessions/${encodeURIComponent(sessionId)}`);
  }

  async logoutUser(userId: string): Promise<void> {
    await this.admin('POST', `/users/${assertUserId(userId)}/logout`);
  }

  // ------------------------------------------------------------------ events

  async listEvents(since: Date, limit: number): Promise<IdpEvent[]> {
    const sinceMs = since.getTime();
    const [userEvents, adminEvents] = await Promise.all([
      this.collect(`/events`, sinceMs, (value) =>
        this.parse(z.array(eventSchema), value).map((event): IdpEvent => ({
          kind: 'user',
          id:
            event.id ??
            contentId([event.time, event.type, event.userId, event.sessionId, event.ipAddress]),
          time: new Date(event.time),
          type: event.type,
          userId: event.userId ?? null,
          sessionId: event.sessionId ?? null,
          clientId: event.clientId ?? null,
          ipAddress: event.ipAddress ?? null,
          error: event.error ?? null,
          resourceType: null,
          resourcePath: null,
          details: event.details ?? {},
        })),
      ),
      this.collect(`/admin-events`, sinceMs, (value) =>
        this.parse(z.array(adminEventSchema), value).map((event): IdpEvent => ({
          kind: 'admin',
          id:
            event.id ??
            contentId([
              event.time,
              event.operationType,
              event.resourcePath,
              event.authDetails?.userId,
            ]),
          time: new Date(event.time),
          type: event.operationType,
          userId: event.authDetails?.userId ?? null,
          sessionId: null,
          clientId: event.authDetails?.clientId ?? null,
          ipAddress: event.authDetails?.ipAddress ?? null,
          error: event.error ?? null,
          resourceType: event.resourceType ?? null,
          resourcePath: event.resourcePath ?? null,
          details: {},
        })),
      ),
    ]);
    return [...userEvents, ...adminEvents]
      .filter((event) => event.time.getTime() >= sinceMs)
      .sort((a, b) => a.time.getTime() - b.time.getTime())
      .slice(0, limit);
  }

  /**
   * Keycloak returns events newest first. Pages back until `sinceMs` (bounded by MAX_PAGES), so
   * that the caller can process the oldest events first and advance its cursor without gaps.
   */
  private async collect(
    path: string,
    sinceMs: number,
    map: (value: unknown) => IdpEvent[],
  ): Promise<IdpEvent[]> {
    const result: IdpEvent[] = [];
    for (let page = 0; page < MAX_PAGES; page += 1) {
      const params = new URLSearchParams({
        dateFrom: String(sinceMs),
        first: String(page * PAGE_SIZE),
        max: String(PAGE_SIZE),
      });
      const batch = map(await this.admin('GET', `${path}?${params.toString()}`));
      result.push(...batch);
      if (batch.length < PAGE_SIZE || batch.some((event) => event.time.getTime() < sinceMs)) break;
    }
    return result;
  }

  async ping(timeoutMs: number): Promise<void> {
    const response = await this.send(this.urls.issuer, { method: 'GET' }, timeoutMs);
    if (!response.ok) {
      throw new IdentityProviderError(`Keycloak realm answered HTTP ${response.status}`, 503);
    }
  }
}
