'use client';

import { ROLE_LABELS } from '@cve/contracts';
import { LogOut, Settings, UserCircle2 } from 'lucide-react';
import Link from 'next/link';
import { useState, type ReactElement } from 'react';
import { toast } from 'sonner';
import { z } from 'zod';

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

const logoutResponseSchema = z.object({ redirectTo: z.string() });

/** Ends the session on the server, then follows the sign-out redirect (Keycloak or /signed-out). */
async function signOut(): Promise<void> {
  const response = await fetch('/session/logout', {
    method: 'POST',
    headers: { 'x-cve-client': 'web', accept: 'application/json' },
    credentials: 'same-origin',
    cache: 'no-store',
  });
  const parsed = logoutResponseSchema.safeParse(response.ok ? await response.json() : null);
  if (!parsed.success) throw new Error(`Sign-out failed with HTTP ${response.status}`);
  window.location.assign(parsed.data.redirectTo);
}

export function UserMenu(): ReactElement {
  const me = useMe();
  const [signingOut, setSigningOut] = useState(false);
  const profile = me.data?.data;
  const name = profile === undefined ? 'Account' : (profile.displayName ?? profile.username);
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          className="gap-2 px-2"
          aria-label="Account menu"
          data-testid="user-menu"
        >
          <UserCircle2 className="size-5" aria-hidden="true" />
          <span className="hidden max-w-40 truncate md:inline">{name}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>
          <span className="block text-sm text-foreground">{name}</span>
          {profile === undefined ? null : (
            <span className="block">
              {profile.roles.length === 0
                ? 'No platform role'
                : profile.roles.map((role) => ROLE_LABELS[role]).join(', ')}
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
          disabled={signingOut}
          onSelect={() => {
            setSigningOut(true);
            signOut().catch(() => {
              setSigningOut(false);
              toast.error('Sign-out failed. Try again.');
            });
          }}
        >
          <LogOut aria-hidden="true" /> Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
