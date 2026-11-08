'use client';

import { ROLE_LABELS } from '@cve/contracts';
import { LogOut, Settings, UserCircle2 } from 'lucide-react';
import Link from 'next/link';
import { useRef, type ReactElement } from 'react';

import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { useMe } from '@/features/auth/use-me';

export function UserMenu(): ReactElement {
  const me = useMe();
  const formRef = useRef<HTMLFormElement>(null);
  const profile = me.data?.data;
  const name = profile === undefined ? 'Account' : (profile.displayName ?? profile.username);
  return (
    <>
      {/* Logout is a same-origin POST so it cannot be triggered by a cross-site link. */}
      <form ref={formRef} method="post" action="/session/logout" className="hidden" />
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" className="gap-2 px-2" aria-label="Account menu" data-testid="user-menu">
            <UserCircle2 className="size-5" aria-hidden="true" />
            <span className="hidden max-w-40 truncate md:inline">{name}</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel>
            <span className="block text-sm text-foreground">{name}</span>
            {profile === undefined ? null : (
              <span className="block">
                {profile.roles.length === 0 ? 'No platform role' : profile.roles.map((role) => ROLE_LABELS[role]).join(', ')}
              </span>
            )}
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem asChild>
            <Link href="/settings">
              <Settings aria-hidden="true" /> Settings
            </Link>
          </DropdownMenuItem>
          <DropdownMenuItem
            onSelect={() => {
              formRef.current?.requestSubmit();
            }}
          >
            <LogOut aria-hidden="true" /> Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}
