import 'reflect-metadata';

import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  auditEventSchema,
  credentialActionLinkSchema,
  domainEventEnvelopeSchema,
  roleDescriptionSchema,
  userProfileSchema,
  userSessionSchema,
  userSummarySchema,
  type Role,
} from '@cve/contracts';
import { createTestTokenIssuer, type TestTokenIssuer } from '@cve/testing/auth';

import { startIdentityApp, type IdentityTestContext } from './support.js';

let issuer: TestTokenIssuer;
let ctx: IdentityTestContext;

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

/** Creates a Keycloak user with roles and returns a token for one of its sessions. */
async function login(roles: Role[], extra: Record<string, unknown> = {}) {
  const id = ctx.idp.addUser(roles);
  const sid = ctx.idp.addSession(id);
  const token = await issuer.tokenFor(id, roles, { sid, ...extra });
  return { id, sid, token, headers: bearer(token) };
}

beforeAll(async () => {
  issuer = await createTestTokenIssuer();
  ctx = await startIdentityApp(issuer);
});

afterAll(async () => {
  await ctx.t.close();
});

beforeEach(() => {
  ctx.idp.users.clear();
  ctx.idp.calls.length = 0;
  ctx.idp.unavailable = false;
  ctx.audit.entries.length = 0;
  ctx.audit.outbox.length = 0;
});

describe('private endpoints', () => {
  it.each([
    ['get', '/api/v1/me'],
    ['patch', '/api/v1/me'],
    ['get', '/api/v1/me/sessions'],
    ['post', '/api/v1/auth/logout'],
    ['get', '/api/v1/users'],
    ['put', `/api/v1/users/${randomUUID()}/roles`],
    ['get', '/api/v1/roles'],
    ['get', '/api/v1/permissions'],
    ['get', '/api/v1/audit-logs'],
  ] as const)('%s %s requires a bearer token', async (method, path) => {
    const res = await ctx.t.http[method](path).expect(401);
    expect(res.body).toMatchObject({ error: { code: 'UNAUTHORIZED' } });
  });

  it('rejects a token for another audience', async () => {
    const token = await issuer.sign(
      { sub: randomUUID(), roles: ['viewer'] },
      { audience: 'account' },
    );
    await ctx.t.http.get('/api/v1/me').set(bearer(token)).expect(401);
  });
});

describe('profile', () => {
  it('returns the caller profile with roles and permissions and creates it on first sight', async () => {
    const user = await login(['security-analyst']);
    const res = await ctx.t.http.get('/api/v1/me').set(user.headers).expect(200);
    const profile = userProfileSchema.parse((res.body as { data: unknown }).data);
    expect(profile.id).toBe(user.id);
    expect(profile.roles).toEqual(['security-analyst']);
    expect(profile.permissions).toContain('report:create');
    expect(profile.timezone).toBe('UTC');
    expect(ctx.profiles.profiles.has(user.id)).toBe(true);
  });

  it('updates names in Keycloak and preferences locally, with an audit entry', async () => {
    const user = await login(['viewer']);
    const res = await ctx.t.http
      .patch('/api/v1/me')
      .set(user.headers)
      .send({ firstName: 'Ada', displayName: 'Ada L.', timezone: 'Europe/Berlin' })
      .expect(200);
    const profile = userProfileSchema.parse((res.body as { data: unknown }).data);
    expect(profile).toMatchObject({
      firstName: 'Ada',
      displayName: 'Ada L.',
      timezone: 'Europe/Berlin',
    });
    expect(ctx.idp.users.get(user.id)?.user.firstName).toBe('Ada');
    expect(ctx.audit.actions()).toEqual(['identity.profile.updated:success']);
  });

  it('rejects unknown fields such as email or password', async () => {
    const user = await login(['viewer']);
    const res = await ctx.t.http
      .patch('/api/v1/me')
      .set(user.headers)
      .send({ password: 'hunter2hunter2' })
      .expect(400);
    expect(res.body).toMatchObject({ error: { code: 'BAD_REQUEST' } });
    expect((res.body as { error: { details?: unknown[] } }).error.details?.length).toBeGreaterThan(
      0,
    );
    expect(ctx.idp.calls).toEqual([]);
  });

  it('offers Keycloak credential actions instead of handling passwords', async () => {
    const user = await login(['viewer']);
    const res = await ctx.t.http
      .get('/api/v1/me/credentials/actions')
      .set(user.headers)
      .expect(200);
    const links = (res.body as { data: unknown[] }).data.map((link) =>
      credentialActionLinkSchema.parse(link),
    );
    const password = new URL(links.find((link) => link.action === 'update-password')!.url);
    expect(password.origin + password.pathname).toBe(
      'http://keycloak.test/auth/realms/cve-platform/protocol/openid-connect/auth',
    );
    expect(password.searchParams.get('kc_action')).toBe('UPDATE_PASSWORD');
    expect(password.searchParams.get('client_id')).toBe('cve-web');
  });

  it('answers 503 when Keycloak is unavailable for an update', async () => {
    const user = await login(['viewer']);
    ctx.idp.unavailable = true;
    await ctx.t.http.patch('/api/v1/me').set(user.headers).send({ lastName: 'L' }).expect(503);
  });
});

describe('sessions and logout', () => {
  it('lists the caller sessions and marks the current one', async () => {
    const user = await login(['viewer']);
    ctx.idp.addSession(user.id);
    const res = await ctx.t.http.get('/api/v1/me/sessions').set(user.headers).expect(200);
    const sessions = (res.body as { data: unknown[] }).data.map((s) => userSessionSchema.parse(s));
    expect(sessions).toHaveLength(2);
    expect(sessions.filter((s) => s.current).map((s) => s.id)).toEqual([user.sid]);
  });

  it('revokes one of the caller sessions but not sessions of other users', async () => {
    const user = await login(['viewer']);
    const other = await login(['viewer']);
    const second = ctx.idp.addSession(user.id);
    await ctx.t.http.delete(`/api/v1/me/sessions/${second}`).set(user.headers).expect(204);
    expect(ctx.idp.calls).toContain(`deleteSession:${second}`);
    await ctx.t.http.delete(`/api/v1/me/sessions/${other.sid}`).set(user.headers).expect(404);
    expect(ctx.idp.calls).not.toContain(`deleteSession:${other.sid}`);
  });

  it('logs out the current Keycloak session and publishes an event through the outbox', async () => {
    const user = await login(['viewer']);
    const res = await ctx.t.http.post('/api/v1/auth/logout').set(user.headers).expect(200);
    expect(res.body).toEqual({ data: { revokedSessions: 1 } });
    expect(ctx.idp.calls).toEqual([`deleteSession:${user.sid}`]);
    expect(ctx.audit.actions()).toEqual(['identity.session.logged-out:success']);
    const event = domainEventEnvelopeSchema.parse(ctx.audit.outbox[0]);
    expect(event).toMatchObject({
      eventType: 'identity.session.revoked',
      producer: 'identity-service',
      payload: { userId: user.id, sessionId: user.sid, reason: 'logout' },
    });
  });

  it('logs out everywhere on request', async () => {
    const user = await login(['viewer']);
    ctx.idp.addSession(user.id);
    const res = await ctx.t.http
      .post('/api/v1/auth/logout')
      .set(user.headers)
      .send({ allSessions: true })
      .expect(200);
    expect(res.body).toEqual({ data: { revokedSessions: 2 } });
    expect(ctx.idp.calls).toEqual([`logoutUser:${user.id}`]);
  });

  it('keeps logout idempotent when the session is already gone', async () => {
    const user = await login(['viewer']);
    await ctx.idp.deleteSession(user.sid);
    const res = await ctx.t.http.post('/api/v1/auth/logout').set(user.headers).expect(200);
    expect(res.body).toEqual({ data: { revokedSessions: 0 } });
  });
});

describe('user administration', () => {
  it('requires user:read to list users and records the denial', async () => {
    const analyst = await login(['security-analyst']);
    await ctx.t.http.get('/api/v1/users').set(analyst.headers).expect(403);
    await new Promise((resolve) => setImmediate(resolve));
    expect(ctx.audit.actions()).toEqual(['identity.access.denied:denied']);
  });

  it('lists users with effective roles and pagination', async () => {
    const admin = await login(['administrator']);
    const researcher = ctx.idp.addUser(['vulnerability-researcher']);
    const res = await ctx.t.http.get('/api/v1/users?pageSize=10').set(admin.headers).expect(200);
    const body = res.body as { data: unknown[]; meta: { totalItems: number } };
    const users = body.data.map((user) => userSummarySchema.parse(user));
    expect(body.meta.totalItems).toBe(2);
    expect(users.find((u) => u.id === researcher)?.roles).toEqual([
      'vulnerability-researcher',
      'viewer',
    ]);
  });

  it('validates path and query parameters', async () => {
    const admin = await login(['administrator']);
    await ctx.t.http.get('/api/v1/users/not-a-uuid').set(admin.headers).expect(400);
    await ctx.t.http.get('/api/v1/users?pageSize=1000').set(admin.headers).expect(400);
    await ctx.t.http.get(`/api/v1/users/${randomUUID()}`).set(admin.headers).expect(404);
  });

  it('lets an administrator grant and revoke non-privileged roles', async () => {
    const admin = await login(['administrator']);
    const target = ctx.idp.addUser(['viewer']);
    ctx.idp.addSession(target);
    const res = await ctx.t.http
      .put(`/api/v1/users/${target}/roles`)
      .set(admin.headers)
      .send({ roles: ['security-analyst'], reason: 'Joined the SOC' })
      .expect(200);
    expect(userSummarySchema.parse((res.body as { data: unknown }).data).roles).toEqual([
      'security-analyst',
      'viewer',
    ]);
    expect(ctx.idp.calls).toEqual([
      `addRoles:${target}:security-analyst`,
      `removeRoles:${target}:viewer`,
      `logoutUser:${target}`,
    ]);
    expect(ctx.audit.actions()).toEqual([
      'identity.user.roles-changed:success',
      'identity.session.revoked:success',
    ]);
    expect(ctx.audit.outbox.map((event) => event.eventType)).toEqual([
      'identity.user.roles-changed',
      'identity.session.revoked',
    ]);
  });

  it('does not touch sessions when roles are only added', async () => {
    const admin = await login(['administrator']);
    const target = ctx.idp.addUser(['viewer']);
    await ctx.t.http
      .put(`/api/v1/users/${target}/roles`)
      .set(admin.headers)
      .send({ roles: ['viewer', 'vulnerability-researcher'] })
      .expect(200);
    expect(ctx.idp.calls).toEqual([`addRoles:${target}:vulnerability-researcher`]);
  });

  it('prevents administrators from granting privileged roles', async () => {
    const admin = await login(['administrator']);
    const target = ctx.idp.addUser(['viewer']);
    const res = await ctx.t.http
      .put(`/api/v1/users/${target}/roles`)
      .set(admin.headers)
      .send({ roles: ['administrator'] })
      .expect(403);
    expect((res.body as { error: { message: string } }).error.message).toContain('administrator');
    expect(ctx.idp.calls).toEqual([]);
    expect(ctx.audit.actions()).toEqual(['identity.user.roles-changed:denied']);
  });

  it('prevents administrators from managing privileged accounts', async () => {
    const admin = await login(['administrator']);
    const otherAdmin = ctx.idp.addUser(['administrator']);
    await ctx.t.http
      .patch(`/api/v1/users/${otherAdmin}/status`)
      .set(admin.headers)
      .send({ enabled: false })
      .expect(403);
    await ctx.t.http.post(`/api/v1/users/${otherAdmin}/logout`).set(admin.headers).expect(403);
    expect(ctx.idp.calls).toEqual([]);
  });

  it('lets a super admin grant administrator', async () => {
    const root = await login(['super-admin']);
    const target = ctx.idp.addUser(['viewer']);
    await ctx.t.http
      .put(`/api/v1/users/${target}/roles`)
      .set(root.headers)
      .send({ roles: ['administrator'] })
      .expect(200);
    expect(ctx.idp.users.get(target)?.roles.has('administrator')).toBe(true);
  });

  it('forbids changing your own roles or status', async () => {
    const root = await login(['super-admin']);
    await ctx.t.http
      .put(`/api/v1/users/${root.id}/roles`)
      .set(root.headers)
      .send({ roles: ['viewer'] })
      .expect(403);
    await ctx.t.http
      .patch(`/api/v1/users/${root.id}/status`)
      .set(root.headers)
      .send({ enabled: false })
      .expect(403);
  });

  it('keeps at least one enabled super admin', async () => {
    const root = await login(['super-admin']);
    const onlyOther = ctx.idp.addUser(['super-admin']);
    // Disable the caller's account in the fake so the target is the last enabled holder.
    const self = ctx.idp.users.get(root.id)!;
    self.user = { ...self.user, enabled: false };
    await ctx.t.http
      .put(`/api/v1/users/${onlyOther}/roles`)
      .set(root.headers)
      .send({ roles: ['administrator'] })
      .expect(409);
    await ctx.t.http
      .patch(`/api/v1/users/${onlyOther}/status`)
      .set(root.headers)
      .send({ enabled: false })
      .expect(409);
    self.user = { ...self.user, enabled: true };
    await ctx.t.http
      .patch(`/api/v1/users/${onlyOther}/status`)
      .set(root.headers)
      .send({ enabled: false })
      .expect(200);
  });

  it('disables a user and ends their sessions', async () => {
    const admin = await login(['administrator']);
    const target = ctx.idp.addUser(['viewer']);
    ctx.idp.addSession(target);
    const res = await ctx.t.http
      .patch(`/api/v1/users/${target}/status`)
      .set(admin.headers)
      .send({ enabled: false, reason: 'Left the company' })
      .expect(200);
    expect(userSummarySchema.parse((res.body as { data: unknown }).data).enabled).toBe(false);
    expect(ctx.idp.calls).toEqual([`updateUser:${target}`, `logoutUser:${target}`]);
    expect(ctx.audit.outbox.map((event) => event.eventType)).toEqual([
      'identity.user.status-changed',
      'identity.session.revoked',
    ]);
  });

  it('requires a password update through Keycloak without handling the password', async () => {
    const admin = await login(['administrator']);
    const target = ctx.idp.addUser(['viewer']);
    const res = await ctx.t.http
      .post(`/api/v1/users/${target}/credentials/require-password-update`)
      .set(admin.headers)
      .expect(200);
    expect(userSummarySchema.parse((res.body as { data: unknown }).data).requiredActions).toEqual([
      'UPDATE_PASSWORD',
    ]);
    expect(ctx.idp.calls).toContain(`logoutUser:${target}`);
  });

  it('lets session managers list and revoke sessions of another user', async () => {
    const admin = await login(['administrator']);
    const target = ctx.idp.addUser(['viewer']);
    const sid = ctx.idp.addSession(target);
    const res = await ctx.t.http
      .get(`/api/v1/users/${target}/sessions`)
      .set(admin.headers)
      .expect(200);
    expect((res.body as { data: unknown[] }).data).toHaveLength(1);
    await ctx.t.http
      .delete(`/api/v1/users/${target}/sessions/${sid}`)
      .set(admin.headers)
      .expect(204);
    expect(ctx.idp.calls).toEqual([`deleteSession:${sid}`]);
  });
});

describe('roles and permissions catalog', () => {
  it('is available to every authenticated user', async () => {
    const viewer = await login(['viewer']);
    const res = await ctx.t.http.get('/api/v1/roles').set(viewer.headers).expect(200);
    const roles = (res.body as { data: unknown[] }).data.map((r) => roleDescriptionSchema.parse(r));
    expect(roles.map((r) => r.role)).toEqual([
      'super-admin',
      'administrator',
      'security-analyst',
      'vulnerability-researcher',
      'viewer',
    ]);
    expect(roles.find((r) => r.role === 'administrator')?.privileged).toBe(true);
    const permissions = await ctx.t.http.get('/api/v1/permissions').set(viewer.headers).expect(200);
    expect((permissions.body as { data: unknown[] }).data.length).toBeGreaterThan(10);
  });
});

describe('audit log', () => {
  it('requires audit:read and returns paginated, filterable entries', async () => {
    const viewer = await login(['viewer']);
    const admin = await login(['administrator']);
    await ctx.t.http
      .patch('/api/v1/me')
      .set(viewer.headers)
      .send({ jobTitle: 'Analyst' })
      .expect(200);
    await ctx.t.http.get('/api/v1/audit-logs').set(viewer.headers).expect(403);

    const res = await ctx.t.http
      .get('/api/v1/audit-logs?action=identity.profile.updated&pageSize=5')
      .set(admin.headers)
      .expect(200);
    const body = res.body as { data: unknown[]; meta: { totalItems: number; pageSize: number } };
    expect(body.meta).toMatchObject({ totalItems: 1, pageSize: 5 });
    const entry = auditEventSchema.parse(body.data[0]);
    expect(entry).toMatchObject({ actorId: viewer.id, outcome: 'success', resourceId: viewer.id });

    const one = await ctx.t.http
      .get(`/api/v1/audit-logs/${entry.id}`)
      .set(admin.headers)
      .expect(200);
    expect((one.body as { data: { id: string } }).data.id).toBe(entry.id);
    await ctx.t.http.get('/api/v1/audit-logs?outcome=maybe').set(admin.headers).expect(400);
  });
});
