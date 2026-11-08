'use client';

import { ChevronDown, Search, X } from 'lucide-react';
import { useEffect, useState, type ReactElement, type ReactNode } from 'react';

import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, type SelectOption } from '@/components/ui/select';
import { useDebouncedValue } from '@/hooks/use-debounced-value';
import { cn } from '@/lib/utils';

export function FilterBar({
  children,
  onReset,
  className,
}: {
  children: ReactNode;
  onReset?: () => void;
  className?: string | undefined;
}): ReactElement {
  return (
    <div
      role="search"
      className={cn(
        'flex flex-wrap items-end gap-3 rounded-xl border border-border bg-card p-4',
        className,
      )}
    >
      {children}
      {onReset === undefined ? null : (
        <Button variant="ghost" size="sm" onClick={onReset} className="ml-auto">
          <X aria-hidden="true" /> Clear filters
        </Button>
      )}
    </div>
  );
}

export function FilterField({
  label,
  htmlFor,
  children,
  className,
}: {
  label: string;
  htmlFor?: string;
  children: ReactNode;
  className?: string | undefined;
}): ReactElement {
  return (
    <div className={cn('flex min-w-36 flex-col gap-1.5', className)}>
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
    </div>
  );
}

/** Text search that commits after the user pauses typing (and only with `minLength` chars). */
export function SearchFilter({
  id,
  label,
  value,
  onChange,
  placeholder,
  minLength = 2,
  className,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  minLength?: number;
  className?: string | undefined;
}): ReactElement {
  const [text, setText] = useState(value);
  const debounced = useDebouncedValue(text, 350);
  useEffect(() => {
    setText(value);
  }, [value]);
  useEffect(() => {
    const trimmed = debounced.trim();
    const committed = trimmed.length >= minLength ? trimmed : '';
    if (committed !== value) onChange(committed);
  }, [debounced]);
  return (
    <FilterField label={label} htmlFor={id} className={cn('min-w-56 flex-1', className)}>
      <div className="relative">
        <Search
          className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden="true"
        />
        <Input
          id={id}
          type="search"
          value={text}
          placeholder={placeholder}
          maxLength={200}
          className="pl-8"
          onChange={(event) => {
            setText(event.target.value);
          }}
        />
      </div>
    </FilterField>
  );
}

export function SelectFilter({
  id,
  label,
  value,
  options,
  onChange,
  placeholder = 'Any',
  className,
}: {
  id: string;
  label: string;
  value: string;
  options: readonly SelectOption[];
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string | undefined;
}): ReactElement {
  return (
    <FilterField label={label} htmlFor={id} className={className}>
      <Select
        id={id}
        value={value}
        options={options}
        placeholder={placeholder}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      />
    </FilterField>
  );
}

export function MultiSelectFilter({
  label,
  values,
  options,
  onChange,
}: {
  label: string;
  values: readonly string[];
  options: readonly SelectOption[];
  onChange: (values: string[]) => void;
}): ReactElement {
  const summary =
    values.length === 0
      ? 'Any'
      : values.length <= 2
        ? options
            .filter((option) => values.includes(option.value))
            .map((option) => option.label)
            .join(', ')
        : `${values.length} selected`;
  return (
    <FilterField label={label}>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            className="justify-between font-normal"
            aria-label={`${label}: ${summary}`}
          >
            <span className="truncate">{summary}</span>
            <ChevronDown className="text-muted-foreground" aria-hidden="true" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start">
          <DropdownMenuLabel>{label}</DropdownMenuLabel>
          <DropdownMenuSeparator />
          {options.map((option) => (
            <DropdownMenuCheckboxItem
              key={option.value}
              checked={values.includes(option.value)}
              onSelect={(event) => {
                event.preventDefault();
              }}
              onCheckedChange={(checked) => {
                onChange(
                  checked
                    ? [...values, option.value]
                    : values.filter((value) => value !== option.value),
                );
              }}
            >
              {option.label}
            </DropdownMenuCheckboxItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
    </FilterField>
  );
}

export function optionsFrom(
  values: readonly string[],
  label: (value: string) => string,
): SelectOption[] {
  return values.map((value) => ({ value, label: label(value) }));
}
