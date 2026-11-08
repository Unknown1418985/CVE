'use client';

import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useCallback, useMemo } from 'react';

export type SearchPatch = Readonly<Record<string, string | readonly string[] | number | undefined | null>>;

/**
 * Filter, sort and pagination state kept in the URL, so views can be bookmarked and shared.
 * Any change other than `page` returns to the first page.
 */
export function useSearchState<K extends string>(defaults: Readonly<Record<K, string>>) {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  const values = useMemo(() => {
    const result = { ...defaults } as Record<K, string>;
    for (const key of Object.keys(defaults) as K[]) {
      const value = params.get(key);
      if (value !== null) result[key] = value;
    }
    return result;
  }, [params, defaults]);

  const update = useCallback(
    (patch: SearchPatch) => {
      const next = new URLSearchParams(params.toString());
      for (const [key, raw] of Object.entries(patch)) {
        const value = Array.isArray(raw) ? (raw as readonly string[]).join(',') : raw;
        const text = value === undefined || value === null ? '' : String(value);
        const fallback = (defaults as Readonly<Record<string, string>>)[key];
        if (text === '' || text === fallback) next.delete(key);
        else next.set(key, text);
      }
      if (!Object.hasOwn(patch, 'page')) next.delete('page');
      const query = next.toString();
      router.replace(query === '' ? pathname : `${pathname}?${query}`, { scroll: false });
    },
    [params, router, pathname, defaults],
  );

  const reset = useCallback(() => {
    router.replace(pathname, { scroll: false });
  }, [router, pathname]);

  return { values, update, reset };
}

/** Parses a comma-separated list parameter. */
export function listValue(value: string): string[] {
  return value === '' ? [] : value.split(',').filter((entry) => entry !== '');
}

/** Positive integer page parameter with a fallback. */
export function intValue(value: string, fallback: number): number {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
