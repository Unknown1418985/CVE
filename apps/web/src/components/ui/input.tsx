import type { InputHTMLAttributes, ReactElement, Ref } from 'react';

import { cn } from '@/lib/utils';

export const fieldClassName =
  'flex h-9 w-full rounded-md border border-border bg-background px-3 py-1 text-sm shadow-xs transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-status-down';

export function Input({
  className,
  ref,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { ref?: Ref<HTMLInputElement> }): ReactElement {
  return <input ref={ref} className={cn(fieldClassName, className)} {...props} />;
}
