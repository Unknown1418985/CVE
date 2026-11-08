import { ChevronDown } from 'lucide-react';
import type { ReactElement, Ref, SelectHTMLAttributes } from 'react';

import { cn } from '@/lib/utils';

import { fieldClassName } from './input';

export interface SelectOption {
  readonly value: string;
  readonly label: string;
}

/** Native select styled like the other fields (accessible and keyboard-friendly by default). */
export function Select({
  className,
  options,
  placeholder,
  ref,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement> & {
  options: readonly SelectOption[];
  placeholder?: string;
  ref?: Ref<HTMLSelectElement>;
}): ReactElement {
  return (
    <div className={cn('relative', className)}>
      <select ref={ref} className={cn(fieldClassName, 'appearance-none pr-8')} {...props}>
        {placeholder === undefined ? null : <option value="">{placeholder}</option>}
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      <ChevronDown
        aria-hidden="true"
        className="pointer-events-none absolute top-1/2 right-2.5 size-4 -translate-y-1/2 text-muted-foreground"
      />
    </div>
  );
}
