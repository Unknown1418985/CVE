'use client';

import { ShieldHalf } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { ReactElement } from 'react';

import { Skeleton } from '@/components/ui/skeleton';
import { isActiveSection, visibleNavigation, type NavigationItem } from '@/config/navigation';
import { useMe } from '@/features/auth/use-me';
import { cn } from '@/lib/utils';

const GROUPS: readonly NavigationItem['group'][] = ['Intelligence', 'Operations', 'Administration'];

export function SidebarNav({ onNavigate }: { onNavigate?: (() => void) | undefined }): ReactElement {
  const pathname = usePathname();
  const me = useMe();
  const permissions = me.data === undefined ? undefined : new Set(me.data.data.permissions);
  const items = visibleNavigation(permissions);

  return (
    <nav aria-label="Main navigation" className="flex flex-col gap-5 px-3 pb-6">
      {GROUPS.map((group) => {
        const groupItems = items.filter((item) => item.group === group);
        if (groupItems.length === 0) return null;
        return (
          <div key={group}>
            <p className="px-3 pb-1.5 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">{group}</p>
            <ul className="flex flex-col gap-0.5">
              {groupItems.map((item) => {
                const active = isActiveSection(item.href, pathname);
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      {...(onNavigate === undefined ? {} : { onClick: onNavigate })}
                      aria-current={active ? 'page' : undefined}
                      className={cn(
                        'flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                        active ? 'bg-muted font-medium text-foreground' : 'text-muted-foreground',
                      )}
                    >
                      <item.icon className="size-4 shrink-0" aria-hidden="true" />
                      {item.label}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        );
      })}
      {me.isPending ? (
        <div className="flex flex-col gap-2 px-3" aria-hidden="true">
          <Skeleton className="h-7" />
          <Skeleton className="h-7" />
          <Skeleton className="h-7" />
        </div>
      ) : null}
    </nav>
  );
}

export function Brand(): ReactElement {
  return (
    <Link href="/" className="flex items-center gap-2 px-5 py-4 focus-visible:outline-none">
      <ShieldHalf className="size-5 text-primary" aria-hidden="true" />
      <span className="text-sm font-semibold tracking-tight">CVE Intelligence Platform</span>
    </Link>
  );
}
