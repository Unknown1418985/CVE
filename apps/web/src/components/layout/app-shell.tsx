'use client';

import { Menu } from 'lucide-react';
import { useState, type ReactElement, type ReactNode } from 'react';

import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog';
import { GlobalSearch } from '@/features/search/global-search';

import { Brand, SidebarNav } from './sidebar';
import { UserMenu } from './user-menu';

export function AppShell({ children }: { children: ReactNode }): ReactElement {
  const [mobileOpen, setMobileOpen] = useState(false);
  return (
    <div className="flex min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-md focus:bg-card focus:px-3 focus:py-2"
      >
        Skip to content
      </a>
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 overflow-y-auto border-r border-border bg-sidebar lg:block">
        <Brand />
        <SidebarNav />
      </aside>
      <Dialog open={mobileOpen} onOpenChange={setMobileOpen}>
        <DialogContent className="top-0 left-0 h-full max-h-screen w-72 max-w-[85vw] translate-x-0 translate-y-0 rounded-none border-r p-0">
          <DialogTitle className="sr-only">Navigation</DialogTitle>
          <DialogDescription className="sr-only">Platform sections</DialogDescription>
          <div className="overflow-y-auto">
            <Brand />
            <SidebarNav
              onNavigate={() => {
                setMobileOpen(false);
              }}
            />
          </div>
        </DialogContent>
      </Dialog>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-background/90 px-4 backdrop-blur md:px-6">
          <Button
            variant="ghost"
            size="icon"
            className="lg:hidden"
            aria-label="Open navigation"
            onClick={() => {
              setMobileOpen(true);
            }}
          >
            <Menu aria-hidden="true" />
          </Button>
          <div className="flex flex-1 justify-center lg:justify-start">
            <GlobalSearch />
          </div>
          <UserMenu />
        </header>
        <main id="main" className="flex-1 px-4 py-6 md:px-6 lg:px-8">
          <div className="mx-auto flex max-w-7xl flex-col gap-6">{children}</div>
        </main>
      </div>
    </div>
  );
}
