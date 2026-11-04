import Link from 'next/link';
import type { ReactElement, ReactNode } from 'react';

import { NAVIGATION } from '@/config/navigation';

export function AppShell({ children }: { children: ReactNode }): ReactElement {
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <aside className="border-b border-border bg-sidebar md:w-64 md:shrink-0 md:border-r md:border-b-0">
        <div className="px-5 py-4">
          <p className="text-sm font-semibold tracking-tight">CVE Intelligence Platform</p>
        </div>
        <nav aria-label="Main navigation" className="px-3 pb-4">
          <ul className="flex gap-1 overflow-x-auto md:flex-col md:overflow-visible">
            {NAVIGATION.map((item) => (
              <li key={item.href}>
                {item.available ? (
                  <Link
                    href={item.href}
                    className="block rounded-md px-3 py-2 text-sm whitespace-nowrap hover:bg-muted"
                  >
                    {item.label}
                  </Link>
                ) : (
                  <span
                    aria-disabled="true"
                    title={`Planned for phase ${item.phase}`}
                    className="flex items-center justify-between gap-2 rounded-md px-3 py-2 text-sm whitespace-nowrap text-muted-foreground/70"
                  >
                    {item.label}
                    <span className="text-[10px] uppercase tracking-wide">Planned</span>
                  </span>
                )}
              </li>
            ))}
          </ul>
        </nav>
      </aside>
      <main className="flex-1 px-4 py-6 md:px-8">{children}</main>
    </div>
  );
}
