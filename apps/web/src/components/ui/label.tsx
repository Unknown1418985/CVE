import { Label as LabelPrimitive } from 'radix-ui';
import type { ComponentProps, ReactElement } from 'react';

import { cn } from '@/lib/utils';

export function Label({ className, ...props }: ComponentProps<typeof LabelPrimitive.Root>): ReactElement {
  return (
    <LabelPrimitive.Root
      className={cn('text-xs font-medium text-muted-foreground', className)}
      {...props}
    />
  );
}
