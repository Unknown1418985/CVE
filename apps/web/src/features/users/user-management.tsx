'use client';

import { ROLE_LABELS, type UserSummary } from '@cve/contracts';
import type { ReactElement } from 'react';

import { DataTable, type Column } from '@/components/data/data-table';
import { FilterBar, SearchFilter } from '@/components/data/filters';
import { InternalLink } from '@/components/data/links';
import { PageHeader } from '@/components/data/page-header';
import { ResultsPanel, pagingFromValues } from '@/components/data/results';
import { EnabledBadge } from '@/components/data/status-badges';
import { Badge } from '@/components/ui/badge';
import { useSearchState } from '@/hooks/use-search-state';
import { formatDate, humanize } from '@/lib/format';

import { useUsers } from './api';

const DEFAULTS = { search: '', page: '1', pageSize: '25' } as const;

export function displayName(
  user: Pick<UserSummary, 'firstName' | 'lastName' | 'username'>,
): string {
  const name = [user.firstName, user.lastName]
    .filter((part) => part !== null && part !== '')
    .join(' ');
  return name === '' ? user.username : name;
}

export function RoleBadges({ roles }: { roles: UserSummary['roles'] }): ReactElement {
  if (roles.length === 0) return <span className="text-muted-foreground">No platform role</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {roles.map((role) => (
        <Badge
          key={role}
          variant={role === 'super-admin' || role === 'administrator' ? 'warning' : 'outline'}
        >
          {ROLE_LABELS[role]}
        </Badge>
      ))}
    </div>
  );
}

const COLUMNS: readonly Column<UserSummary>[] = [
  {
    id: 'user',
    header: 'User',
    cell: (row) => (
      <div className="flex flex-col gap-0.5">
        <InternalLink href={`/users/${row.id}`} className="font-medium">
          {displayName(row)}
        </InternalLink>
        <span className="text-xs text-muted-foreground">
          {row.username}
          {row.email === null ? '' : ` · ${row.email}`}
        </span>
      </div>
    ),
  },
  { id: 'roles', header: 'Roles', cell: (row) => <RoleBadges roles={row.roles} /> },
  { id: 'status', header: 'Status', cell: (row) => <EnabledBadge enabled={row.enabled} /> },
  {
    id: 'actions',
    header: 'Pending actions',
    cell: (row) =>
      row.requiredActions.length === 0 ? (
        '—'
      ) : (
        <div className="flex flex-wrap gap-1">
          {row.requiredActions.map((action) => (
            <Badge key={action} variant="muted">
              {humanize(action.toLowerCase())}
            </Badge>
          ))}
        </div>
      ),
  },
  { id: 'email', header: 'Email verified', cell: (row) => (row.emailVerified ? 'Yes' : 'No') },
  { id: 'created', header: 'Created', cell: (row) => formatDate(row.createdAt) },
];

export function UserManagementView(): ReactElement {
  const { values, update } = useSearchState(DEFAULTS);
  const query = useUsers({ search: values.search, ...pagingFromValues(values) });
  return (
    <>
      <PageHeader
        title="User Management"
        description="Accounts are managed in Keycloak. Assign platform roles, enable or disable users and end their sessions here; every change is audited."
      />
      <FilterBar>
        <SearchFilter
          id="user-search"
          label="Search"
          value={values.search}
          minLength={1}
          placeholder="Username, name or email"
          onChange={(search) => {
            update({ search });
          }}
        />
      </FilterBar>
      <ResultsPanel query={query} update={update}>
        <DataTable
          caption="Users"
          columns={COLUMNS}
          rows={query.data?.data}
          loading={query.isPending}
          fetching={query.isFetching}
          getRowKey={(row) => row.id}
          rowHref={(row) => `/users/${row.id}`}
          emptyTitle="No users found"
          emptyDescription={
            values.search === ''
              ? 'Keycloak returned no users for this realm.'
              : 'No user matches this search.'
          }
        />
      </ResultsPanel>
    </>
  );
}
