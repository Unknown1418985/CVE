'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { ROLE_LABELS, type UpdateProfileRequest, type UserProfile } from '@cve/contracts';
import { KeyRound, Smartphone } from 'lucide-react';
import { useState, type ReactElement } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';

import { DetailList, PageHeader, Section } from '@/components/data/page-header';
import { EmptyState, ErrorState, LoadingState, QueryState } from '@/components/data/states';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useMe } from '@/features/auth/use-me';
import { useMySessions, usePermissionCatalog, useRoles } from '@/features/users/api';
import { useRevokeMySession, useUpdateProfile } from '@/features/users/mutations';
import { SessionTable } from '@/features/users/user-detail';
import { describeError } from '@/lib/api/client';
import { formatDateTime } from '@/lib/format';

const NAME = /^[^<>\p{Cc}]*$/u;
const nameField = (label: string, required: boolean) =>
  z
    .string()
    .trim()
    .max(100, `${label} is too long`)
    .regex(NAME, `${label} contains forbidden characters`)
    .refine((value) => !required || value.length > 0, `${label} is required`);

export const profileFormSchema = z.object({
  firstName: nameField('First name', false),
  lastName: nameField('Last name', false),
  displayName: nameField('Display name', false),
  jobTitle: nameField('Job title', false),
  timezone: z
    .string()
    .trim()
    .min(1, 'Select a time zone')
    .refine((value) => {
      try {
        new Intl.DateTimeFormat('en-US', { timeZone: value });
        return true;
      } catch {
        return false;
      }
    }, 'Enter a valid IANA time zone such as Europe/Berlin'),
});
type ProfileForm = z.input<typeof profileFormSchema>;

/** Only the fields that changed; cleared optional fields become null. Names cannot be cleared. */
export function profileChanges(profile: UserProfile, values: z.output<typeof profileFormSchema>): UpdateProfileRequest {
  const changes: Record<string, string | null> = {};
  if (values.firstName !== '' && values.firstName !== (profile.firstName ?? '')) changes['firstName'] = values.firstName;
  if (values.lastName !== '' && values.lastName !== (profile.lastName ?? '')) changes['lastName'] = values.lastName;
  if (values.displayName !== (profile.displayName ?? '')) changes['displayName'] = values.displayName === '' ? null : values.displayName;
  if (values.jobTitle !== (profile.jobTitle ?? '')) changes['jobTitle'] = values.jobTitle === '' ? null : values.jobTitle;
  if (values.timezone !== profile.timezone) changes['timezone'] = values.timezone;
  return changes;
}

function timeZones(): readonly string[] {
  try {
    return Intl.supportedValuesOf('timeZone');
  } catch {
    return [];
  }
}

function ProfileSection({ profile }: { profile: UserProfile }): ReactElement {
  const update = useUpdateProfile();
  const [error, setError] = useState<string | null>(null);
  const form = useForm<ProfileForm>({
    resolver: zodResolver(profileFormSchema),
    defaultValues: {
      firstName: profile.firstName ?? '',
      lastName: profile.lastName ?? '',
      displayName: profile.displayName ?? '',
      jobTitle: profile.jobTitle ?? '',
      timezone: profile.timezone,
    },
  });
  const errors = form.formState.errors;
  const zones = timeZones();

  const submit = form.handleSubmit(async (values) => {
    setError(null);
    const changes = profileChanges(profile, profileFormSchema.parse(values));
    if (Object.keys(changes).length === 0) {
      setError('Nothing to save.');
      return;
    }
    try {
      const saved = await update.mutateAsync(changes);
      const next = saved.data;
      form.reset({
        firstName: next.firstName ?? '',
        lastName: next.lastName ?? '',
        displayName: next.displayName ?? '',
        jobTitle: next.jobTitle ?? '',
        timezone: next.timezone,
      });
    } catch (caught) {
      setError(describeError(caught));
    }
  });

  const field = (name: keyof ProfileForm, label: string, hint?: string) => (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={`profile-${name}`}>{label}</Label>
      <Input id={`profile-${name}`} maxLength={100} aria-invalid={errors[name] !== undefined} {...form.register(name)}
        {...(name === 'timezone' && zones.length > 0 ? { list: 'profile-timezones' } : {})} />
      {errors[name]?.message === undefined ? (hint === undefined ? null : <p className="text-xs text-muted-foreground">{hint}</p>) : (
        <p className="text-xs text-status-down">{errors[name].message}</p>
      )}
    </div>
  );

  return (
    <Section title="Profile" description="Names are stored in Keycloak; display name, job title and time zone in the platform. Email and username are managed in Keycloak.">
      <form className="flex flex-col gap-4" onSubmit={(event) => { void submit(event); }} noValidate>
        <div className="grid gap-4 sm:grid-cols-2">
          {field('firstName', 'First name')}
          {field('lastName', 'Last name')}
          {field('displayName', 'Display name', 'Shown instead of your name when set.')}
          {field('jobTitle', 'Job title')}
          {field('timezone', 'Time zone', 'Dates in the interface are shown in UTC; this is used for reports and notifications.')}
        </div>
        {zones.length > 0 ? <datalist id="profile-timezones">{zones.map((zone) => <option key={zone} value={zone} />)}</datalist> : null}
        <DetailList
          items={[
            { label: 'Username', value: profile.username },
            { label: 'Email', value: `${profile.email ?? '—'}${profile.email !== null && !profile.emailVerified ? ' (not verified)' : ''}` },
            { label: 'Member since', value: formatDateTime(profile.firstSeenAt) },
          ]}
        />
        {error === null ? null : <p role="alert" className="text-sm text-status-down">{error}</p>}
        <div><Button type="submit" disabled={form.formState.isSubmitting || !form.formState.isDirty}>Save profile</Button></div>
      </form>
    </Section>
  );
}

function SecuritySection(): ReactElement {
  return (
    <Section title="Sign-in security" description="Credentials are changed on the Keycloak sign-in page. The platform never receives your password or one-time codes.">
      <div className="flex flex-wrap gap-2">
        <Button asChild variant="outline">
          <a href="/session/login?action=update-password&returnTo=%2Fsettings"><KeyRound aria-hidden="true" /> Change password</a>
        </Button>
        <Button asChild variant="outline">
          <a href="/session/login?action=configure-totp&returnTo=%2Fsettings"><Smartphone aria-hidden="true" /> Set up two-factor authentication</a>
        </Button>
      </div>
    </Section>
  );
}

function SessionsSection(): ReactElement {
  const query = useMySessions();
  const revoke = useRevokeMySession();
  return (
    <Section title="Your active sessions" description="Revoke a session you do not recognise, for example on a lost device. Use Sign out in the user menu to end this session.">
      <QueryState query={query} isEmpty={(data) => data.data.length === 0} empty={<EmptyState title="No active sessions reported" />}>
        {(data) => <SessionTable sessions={data.data} onRevoke={(session) => revoke.mutateAsync({ sessionId: session.id })} />}
      </QueryState>
    </Section>
  );
}

function AccessSection({ profile }: { profile: UserProfile }): ReactElement {
  const roles = useRoles();
  const catalog = usePermissionCatalog();
  const granted = new Set(profile.permissions);
  return (
    <Section title="Access" description="Your roles and the permissions they grant. Roles are assigned by an administrator in User Management.">
      <div className="mb-4 flex flex-wrap gap-1">
        {profile.roles.length === 0 ? <span className="text-sm text-muted-foreground">No platform role assigned.</span> : profile.roles.map((role) => <Badge key={role} variant="info">{ROLE_LABELS[role]}</Badge>)}
      </div>
      <QueryState query={catalog}>
        {(data) => (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Permission</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Granted to you</TableHead>
                <TableHead>Roles</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.data.map((entry) => (
                <TableRow key={entry.permission}>
                  <TableCell className="font-mono-id text-xs">{entry.permission}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{entry.description}</TableCell>
                  <TableCell>{granted.has(entry.permission) ? <Badge variant="success">Yes</Badge> : <Badge variant="muted">No</Badge>}</TableCell>
                  <TableCell className="text-xs">
                    {roles.data === undefined ? '…' : roles.data.data.filter((role) => role.permissions.includes(entry.permission)).map((role) => role.label).join(', ')}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </QueryState>
    </Section>
  );
}

export function SettingsView(): ReactElement {
  const me = useMe();
  return (
    <>
      <PageHeader title="Settings" description="Your profile, sign-in security, sessions and access." />
      {me.isPending ? <LoadingState rows={6} /> : me.isError ? <ErrorState error={me.error} onRetry={() => { void me.refetch(); }} /> : (
        <>
          <ProfileSection key={me.data.data.id} profile={me.data.data} />
          <SecuritySection />
          <SessionsSection />
          <AccessSection profile={me.data.data} />
        </>
      )}
    </>
  );
}
