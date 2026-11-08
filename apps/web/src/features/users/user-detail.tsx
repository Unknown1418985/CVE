'use client';

import { ROLES, ROLE_LABELS, canAssignRole, type Role, type UserSession, type UserSummary } from '@cve/contracts';
import { ArrowLeft, KeyRound, LogOut, ShieldOff, ShieldCheck, X } from 'lucide-react';
import Link from 'next/link';
import { useState, type ReactElement } from 'react';

import { ConfirmDialog } from '@/components/data/confirm-dialog';
import { DetailList, PageHeader, Section } from '@/components/data/page-header';
import { EmptyState, ErrorState, LoadingState, QueryState } from '@/components/data/states';
import { EnabledBadge } from '@/components/data/status-badges';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useCan, useMe } from '@/features/auth/use-me';
import { formatDateTime, formatRelative, humanize } from '@/lib/format';

import { useRoles, useUser, useUserSessions } from './api';
import { useLogoutUser, useRequirePasswordUpdate, useRevokeUserSession, useSetUserRoles, useSetUserStatus } from './mutations';
import { RoleBadges, displayName } from './user-management';

export function sameRoles(a: readonly Role[], b: readonly Role[]): boolean {
  return a.length === b.length && a.every((role) => b.includes(role));
}

function RoleEditor({ user }: { user: UserSummary }): ReactElement | null {
  const me = useMe();
  const roles = useRoles();
  const setRoles = useSetUserRoles();
  const [selected, setSelected] = useState<readonly Role[]>(user.roles);
  const permissions = me.data?.data.permissions;
  if (!permissions?.some((permission) => permission === 'role:assign' || permission === 'role:assign-privileged')) return null;
  const changed = !sameRoles(selected, user.roles);
  const removed = user.roles.filter((role) => !selected.includes(role));
  const isSelf = me.data?.data.id === user.id;
  return (
    <Section title="Platform roles" description="Administrator and Super Admin can only be granted or revoked by a Super Admin. Removing a role ends the user's sessions.">
      <fieldset className="flex flex-col gap-2">
        <legend className="sr-only">Roles</legend>
        {ROLES.map((role) => {
          const allowed = canAssignRole(permissions, role);
          const description = roles.data?.data.find((entry) => entry.role === role);
          const id = `role-${role}`;
          return (
            <label key={role} htmlFor={id} className="flex items-start gap-3 rounded-md border border-border p-3 has-[:disabled]:opacity-60">
              <input
                id={id}
                type="checkbox"
                className="mt-1 size-4 accent-[var(--primary)]"
                checked={selected.includes(role)}
                disabled={!allowed}
                onChange={(event) => {
                  setSelected(event.target.checked ? [...selected, role] : selected.filter((entry) => entry !== role));
                }}
              />
              <span className="flex flex-col gap-0.5">
                <span className="text-sm font-medium">
                  {ROLE_LABELS[role]}
                  {description?.privileged === true ? <Badge variant="warning" className="ml-2">Privileged</Badge> : null}
                </span>
                <span className="text-xs text-muted-foreground">
                  {description === undefined ? '' : `${description.permissions.length} permissions`}
                  {allowed ? '' : ' · You cannot assign this role'}
                </span>
              </span>
            </label>
          );
        })}
      </fieldset>
      <div className="mt-4 flex flex-wrap gap-2">
        <ConfirmDialog
          trigger={<Button disabled={!changed}>Save roles</Button>}
          title={`Change roles of ${user.username}`}
          description={
            <div className="flex flex-col gap-2">
              <p>New roles: {selected.length === 0 ? 'none' : selected.map((role) => ROLE_LABELS[role]).join(', ')}.</p>
              {removed.length > 0 ? <p className="text-status-degraded">Removing {removed.map((role) => ROLE_LABELS[role]).join(', ')} ends every session of this user.</p> : null}
              {isSelf ? <p className="text-status-down">You are changing your own roles.</p> : null}
            </div>
          }
          confirmLabel="Save roles"
          destructive={removed.length > 0}
          reasonLabel="Reason"
          reasonRequired={false}
          onConfirm={async (reason) => { await setRoles.mutateAsync({ userId: user.id, roles: selected, reason }); }}
        />
        {changed ? <Button variant="ghost" onClick={() => { setSelected(user.roles); }}>Discard</Button> : null}
      </div>
    </Section>
  );
}

function AccountActions({ user }: { user: UserSummary }): ReactElement | null {
  const canManage = useCan('user:manage');
  const me = useMe();
  const status = useSetUserStatus();
  const password = useRequirePasswordUpdate();
  if (canManage !== true) return null;
  const isSelf = me.data?.data.id === user.id;
  return (
    <div className="flex flex-wrap gap-2">
      {user.enabled ? (
        <ConfirmDialog
          trigger={<Button variant="destructive" disabled={isSelf} title={isSelf ? 'You cannot disable your own account' : undefined}><ShieldOff aria-hidden="true" /> Disable</Button>}
          title={`Disable ${user.username}`}
          description="The user can no longer sign in and every active session ends immediately."
          confirmLabel="Disable user"
          destructive
          reasonLabel="Reason"
          onConfirm={(reason) => status.mutateAsync({ userId: user.id, enabled: false, reason })}
        />
      ) : (
        <ConfirmDialog
          trigger={<Button><ShieldCheck aria-hidden="true" /> Enable</Button>}
          title={`Enable ${user.username}`}
          description="The user can sign in again with their existing roles."
          confirmLabel="Enable user"
          reasonLabel="Reason"
          onConfirm={(reason) => status.mutateAsync({ userId: user.id, enabled: true, reason })}
        />
      )}
      <ConfirmDialog
        trigger={<Button variant="outline"><KeyRound aria-hidden="true" /> Require password change</Button>}
        title={`Require ${user.username} to change their password`}
        description="Keycloak asks for a new password at the next sign-in. Every active session ends now."
        confirmLabel="Require password change"
        destructive
        onConfirm={() => password.mutateAsync({ userId: user.id })}
      />
    </div>
  );
}

export function SessionTable({
  sessions,
  onRevoke,
  revokeLabel = 'Revoke',
}: {
  sessions: readonly UserSession[];
  onRevoke?: ((session: UserSession) => Promise<unknown>) | undefined;
  revokeLabel?: string;
}): ReactElement {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Started</TableHead>
          <TableHead>Last activity</TableHead>
          <TableHead>IP address</TableHead>
          <TableHead>Clients</TableHead>
          {onRevoke === undefined ? null : <TableHead><span className="sr-only">Actions</span></TableHead>}
        </TableRow>
      </TableHeader>
      <TableBody>
        {sessions.map((session) => (
          <TableRow key={session.id}>
            <TableCell>{formatDateTime(session.startedAt)}{session.current ? <Badge variant="info" className="ml-2">This session</Badge> : null}</TableCell>
            <TableCell title={formatDateTime(session.lastAccessAt)}>{formatRelative(session.lastAccessAt)}</TableCell>
            <TableCell className="font-mono-id text-xs">{session.ipAddress ?? '—'}</TableCell>
            <TableCell className="text-xs">{session.clients.length === 0 ? '—' : session.clients.join(', ')}</TableCell>
            {onRevoke === undefined ? null : (
              <TableCell className="text-right">
                {session.current ? null : (
                  <ConfirmDialog
                    trigger={<Button size="sm" variant="outline"><X aria-hidden="true" /> {revokeLabel}</Button>}
                    title="Revoke session"
                    description="The device using this session is signed out and its refresh token stops working."
                    confirmLabel="Revoke session"
                    destructive
                    onConfirm={() => onRevoke(session)}
                  />
                )}
              </TableCell>
            )}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function Sessions({ user }: { user: UserSummary }): ReactElement | null {
  const canManage = useCan('session:manage');
  const query = useUserSessions(user.id, canManage === true);
  const revoke = useRevokeUserSession();
  const logout = useLogoutUser();
  if (canManage !== true) return null;
  return (
    <Section
      title="Active sessions"
      actions={
        <ConfirmDialog
          trigger={<Button variant="destructive" size="sm"><LogOut aria-hidden="true" /> End all sessions</Button>}
          title={`Sign ${user.username} out everywhere`}
          description="Every active session of this user ends and their refresh tokens stop working."
          confirmLabel="End all sessions"
          destructive
          onConfirm={() => logout.mutateAsync({ userId: user.id })}
        />
      }
    >
      <QueryState query={query} isEmpty={(data) => data.data.length === 0} empty={<EmptyState title="No active sessions" />}>
        {(data) => <SessionTable sessions={data.data} onRevoke={(session) => revoke.mutateAsync({ userId: user.id, sessionId: session.id })} />}
      </QueryState>
    </Section>
  );
}

export function UserDetailView({ userId }: { userId: string }): ReactElement {
  const query = useUser(userId);
  const back = <Link href="/users" className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="size-3" aria-hidden="true" /> Users</Link>;
  if (query.isPending) return <><PageHeader eyebrow={back} title="User" /><LoadingState rows={6} /></>;
  if (query.isError) {
    return (
      <>
        <PageHeader eyebrow={back} title="User" />
        {query.error.isNotFound ? <EmptyState title="User not found" /> : <ErrorState error={query.error} onRetry={() => { void query.refetch(); }} />}
      </>
    );
  }
  const user = query.data.data;
  return (
    <>
      <PageHeader eyebrow={back} title={displayName(user)} description={user.username} actions={<AccountActions user={user} />} />
      <Section title="Account" actions={<EnabledBadge enabled={user.enabled} />}>
        <DetailList
          items={[
            { label: 'Username', value: user.username },
            { label: 'Email', value: user.email ?? '—' },
            { label: 'Email verified', value: user.emailVerified ? 'Yes' : 'No' },
            { label: 'Created', value: formatDateTime(user.createdAt) },
            { label: 'Roles', value: <RoleBadges roles={user.roles} /> },
            { label: 'Pending Keycloak actions', value: user.requiredActions.length === 0 ? 'None' : user.requiredActions.map((action) => humanize(action.toLowerCase())).join(', ') },
            { label: 'User ID', value: <span className="font-mono-id text-xs">{user.id}</span>, wide: true },
          ]}
        />
      </Section>
      <RoleEditor key={user.roles.join(',')} user={user} />
      <Sessions user={user} />
    </>
  );
}
