import { ExternalLink as ExternalIcon } from 'lucide-react';
import Link from 'next/link';
import type { ReactElement, ReactNode } from 'react';

import { cn } from '@/lib/utils';

/** Only http(s) URLs are ever turned into links; anything else is shown as plain text. */
export function isSafeHttpUrl(value: string): boolean {
  if (!URL.canParse(value)) return false;
  const url = new URL(value);
  return (url.protocol === 'https:' || url.protocol === 'http:') && url.username === '' && url.password === '';
}

/**
 * Link to an external, untrusted location (source references, repositories). Opens in a new tab
 * without a referrer or opener, and is marked `nofollow`.
 */
export function ExternalLink({
  href,
  children,
  className,
}: {
  href: string;
  children?: ReactNode;
  className?: string | undefined;
}): ReactElement {
  if (!isSafeHttpUrl(href)) return <span className={cn('break-all', className)}>{children ?? href}</span>;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer nofollow"
      referrerPolicy="no-referrer"
      className={cn('inline-flex items-center gap-1 break-all text-primary hover:underline', className)}
    >
      {children ?? href}
      <ExternalIcon className="size-3 shrink-0" aria-hidden="true" />
    </a>
  );
}

export function CveLink({ cveId, className }: { cveId: string; className?: string }): ReactElement {
  return (
    <Link
      href={`/cves/${encodeURIComponent(cveId)}`}
      className={cn('font-mono-id whitespace-nowrap text-primary hover:underline', className)}
    >
      {cveId}
    </Link>
  );
}

export function InternalLink({
  href,
  children,
  className,
}: {
  href: string;
  children: ReactNode;
  className?: string | undefined;
}): ReactElement {
  return (
    <Link href={href} className={cn('text-primary hover:underline', className)}>
      {children}
    </Link>
  );
}
