'use client';

import {
  cveSummarySchema,
  exploitSummarySchema,
  pocRepositorySchema,
  productSummarySchema,
  vendorSchema,
} from '@cve/contracts';
import { Command } from 'cmdk';
import {
  ArrowRight,
  Bug,
  Building2,
  FolderGit2,
  Loader2,
  Package,
  Search,
  Swords,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import { useEffect, useState, type ReactElement, type ReactNode } from 'react';

import { SeverityBadge } from '@/components/data/status-badges';
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog';
import { visibleNavigation } from '@/config/navigation';
import { usePermissions } from '@/features/auth/use-me';
import { useDebouncedValue } from '@/hooks/use-debounced-value';
import { pageSchema } from '@/lib/api/client';
import { useApiQuery } from '@/lib/api/hooks';

import { parseSearchInput } from './parse-search';

const LIMIT = 5;

function Group({ heading, children }: { heading: string; children: ReactNode }): ReactElement {
  return (
    <Command.Group
      heading={heading}
      className="px-1 py-1.5 [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:pb-1 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:text-muted-foreground"
    >
      {children}
    </Command.Group>
  );
}

function Item({
  value,
  onSelect,
  children,
}: {
  value: string;
  onSelect: () => void;
  children: ReactNode;
}): ReactElement {
  return (
    <Command.Item
      value={value}
      onSelect={onSelect}
      className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm aria-selected:bg-muted [&_svg]:size-4 [&_svg]:shrink-0 [&_svg]:text-muted-foreground"
    >
      {children}
    </Command.Item>
  );
}

/**
 * Global search (Ctrl/⌘+K): jumps to an exact CVE ID, and otherwise searches CVEs, vendors,
 * products, PoC repositories and exploits in the services the user may read.
 */
export function GlobalSearch(): ReactElement {
  const router = useRouter();
  const permissions = usePermissions();
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState('');
  const debounced = useDebouncedValue(input, 250);
  const intent = parseSearchInput(debounced);
  const text = intent.kind === 'text' && intent.query.length >= 2 ? intent.query : null;
  const can = (permission: Parameters<NonNullable<typeof permissions>['has']>[0]): boolean =>
    permissions?.has(permission) === true;

  useEffect(() => {
    const onKey = (event: KeyboardEvent): void => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setOpen((value) => !value);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, []);

  const cves = useApiQuery({
    path: 'cves',
    schema: pageSchema(cveSummarySchema),
    query: { q: text, pageSize: LIMIT, sort: 'publishedAt', order: 'desc' },
    enabled: open && text !== null && can('cve:read'),
  });
  const vendors = useApiQuery({
    path: 'vendors',
    schema: pageSchema(vendorSchema),
    query: { q: text, pageSize: LIMIT, sort: 'cveCount', order: 'desc' },
    enabled: open && text !== null && can('asset:read'),
  });
  const products = useApiQuery({
    path: 'products',
    schema: pageSchema(productSummarySchema),
    query: { q: text, pageSize: LIMIT, sort: 'cveCount', order: 'desc' },
    enabled: open && text !== null && can('asset:read'),
  });
  const repositories = useApiQuery({
    path: 'poc-repositories',
    schema: pageSchema(pocRepositorySchema),
    query: { q: text, pageSize: LIMIT },
    enabled: open && text !== null && can('poc:read'),
  });
  const exploits = useApiQuery({
    path: 'exploits',
    schema: pageSchema(exploitSummarySchema),
    query: { q: text, pageSize: LIMIT },
    enabled: open && text !== null && can('exploit:read'),
  });

  const go = (href: string): void => {
    setOpen(false);
    setInput('');
    router.push(href);
  };

  const loading =
    text !== null &&
    [cves, vendors, products, repositories, exploits].some((query) => query.isFetching);
  const pages = visibleNavigation(permissions).filter(
    (item) => input.trim() !== '' && item.label.toLowerCase().includes(input.trim().toLowerCase()),
  );

  return (
    <>
      <button
        type="button"
        onClick={() => {
          setOpen(true);
        }}
        className="flex h-9 w-full max-w-md items-center gap-2 rounded-md border border-border bg-background px-3 text-sm text-muted-foreground hover:border-primary/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        aria-label="Open global search"
        data-testid="global-search-trigger"
      >
        <Search className="size-4" aria-hidden="true" />
        <span className="flex-1 truncate text-left">Search CVEs, vendors, PoCs, exploits…</span>
        <kbd className="hidden rounded border border-border px-1.5 text-[10px] sm:inline">
          Ctrl K
        </kbd>
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-2xl gap-0 overflow-hidden p-0">
          <DialogTitle className="sr-only">Global search</DialogTitle>
          <DialogDescription className="sr-only">
            Type a CVE ID to open it directly, or search across the platform.
          </DialogDescription>
          <Command shouldFilter={false} label="Global search" loop>
            <div className="flex items-center gap-2 border-b border-border px-3">
              <Search className="size-4 text-muted-foreground" aria-hidden="true" />
              <Command.Input
                value={input}
                onValueChange={setInput}
                maxLength={200}
                placeholder="CVE-2026-1234, vendor, product, repository…"
                className="h-12 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
              />
              {loading ? (
                <Loader2 className="size-4 animate-spin text-muted-foreground" aria-hidden="true" />
              ) : null}
            </div>
            <Command.List className="max-h-[60vh] overflow-y-auto p-1">
              <Command.Empty className="px-3 py-6 text-center text-sm text-muted-foreground">
                {input.trim().length < 2
                  ? 'Type at least two characters.'
                  : loading
                    ? 'Searching…'
                    : 'No matches.'}
              </Command.Empty>
              {intent.kind === 'cve' && can('cve:read') ? (
                <Group heading="Go to">
                  <Item
                    value={`open-${intent.cveId}`}
                    onSelect={() => {
                      go(`/cves/${intent.cveId}`);
                    }}
                  >
                    <Bug aria-hidden="true" /> Open{' '}
                    <span className="font-mono-id">{intent.cveId}</span>
                    <ArrowRight className="ml-auto" aria-hidden="true" />
                  </Item>
                </Group>
              ) : null}
              {intent.kind === 'cpe' && can('asset:read') ? (
                <Group heading="Go to">
                  <Item
                    value="open-cpe"
                    onSelect={() => {
                      go(`/vendors?tab=products&cpe=${encodeURIComponent(intent.cpe)}`);
                    }}
                  >
                    <Package aria-hidden="true" /> Products registered for this CPE name
                  </Item>
                </Group>
              ) : null}
              {pages.length > 0 ? (
                <Group heading="Pages">
                  {pages.map((item) => (
                    <Item
                      key={item.href}
                      value={`page-${item.href}`}
                      onSelect={() => {
                        go(item.href);
                      }}
                    >
                      <item.icon aria-hidden="true" /> {item.label}
                    </Item>
                  ))}
                </Group>
              ) : null}
              {text !== null && can('cve:read') ? (
                <Group heading="CVEs">
                  {cves.data?.data.map((cve) => (
                    <Item
                      key={cve.id}
                      value={`cve-${cve.cveId}`}
                      onSelect={() => {
                        go(`/cves/${cve.cveId}`);
                      }}
                    >
                      <Bug aria-hidden="true" />
                      <span className="font-mono-id">{cve.cveId}</span>
                      <span className="truncate text-muted-foreground">
                        {cve.title ?? cve.description}
                      </span>
                      <span className="ml-auto">
                        <SeverityBadge severity={cve.severity} />
                      </span>
                    </Item>
                  ))}
                  <Item
                    value="all-cves"
                    onSelect={() => {
                      go(`/cves?q=${encodeURIComponent(text)}`);
                    }}
                  >
                    <Search aria-hidden="true" /> Search all CVEs for “{text}”
                    {cves.data === undefined ? null : (
                      <span className="ml-auto text-xs text-muted-foreground">
                        {cves.data.meta.totalItems} matches
                      </span>
                    )}
                  </Item>
                </Group>
              ) : null}
              {vendors.data !== undefined && vendors.data.data.length > 0 ? (
                <Group heading="Vendors">
                  {vendors.data.data.map((vendor) => (
                    <Item
                      key={vendor.id}
                      value={`vendor-${vendor.id}`}
                      onSelect={() => {
                        go(`/vendors/${vendor.id}`);
                      }}
                    >
                      <Building2 aria-hidden="true" /> {vendor.name}
                      <span className="ml-auto text-xs text-muted-foreground">
                        {vendor.cveCount} CVEs
                      </span>
                    </Item>
                  ))}
                </Group>
              ) : null}
              {products.data !== undefined && products.data.data.length > 0 ? (
                <Group heading="Products">
                  {products.data.data.map((product) => (
                    <Item
                      key={product.id}
                      value={`product-${product.id}`}
                      onSelect={() => {
                        go(`/products/${product.id}`);
                      }}
                    >
                      <Package aria-hidden="true" /> {product.vendor.name} {product.name}
                      <span className="ml-auto text-xs text-muted-foreground">
                        {product.cveCount} CVEs
                      </span>
                    </Item>
                  ))}
                </Group>
              ) : null}
              {repositories.data !== undefined && repositories.data.data.length > 0 ? (
                <Group heading="PoC repositories">
                  {repositories.data.data.map((repository) => (
                    <Item
                      key={repository.id}
                      value={`repo-${repository.id}`}
                      onSelect={() => {
                        go(`/pocs/${repository.id}`);
                      }}
                    >
                      <FolderGit2 aria-hidden="true" /> {repository.fullName}
                    </Item>
                  ))}
                </Group>
              ) : null}
              {exploits.data !== undefined && exploits.data.data.length > 0 ? (
                <Group heading="Exploits">
                  {exploits.data.data.map((exploit) => (
                    <Item
                      key={exploit.id}
                      value={`exploit-${exploit.id}`}
                      onSelect={() => {
                        go(`/exploits/${exploit.id}`);
                      }}
                    >
                      <Swords aria-hidden="true" /> {exploit.title ?? exploit.externalId}
                    </Item>
                  ))}
                </Group>
              ) : null}
            </Command.List>
          </Command>
        </DialogContent>
      </Dialog>
    </>
  );
}
