import { CVE_ID_PATTERN, isCpe23 } from '@cve/contracts';

export type SearchIntent =
  | { readonly kind: 'empty' }
  | { readonly kind: 'cve'; readonly cveId: string }
  | { readonly kind: 'cpe'; readonly cpe: string }
  | { readonly kind: 'text'; readonly query: string };

/** Interprets global search input: an exact CVE ID or CPE name jumps straight to it. */
export function parseSearchInput(input: string): SearchIntent {
  const text = input.trim().slice(0, 200);
  if (text === '') return { kind: 'empty' };
  const upper = text.toUpperCase();
  if (CVE_ID_PATTERN.test(upper)) return { kind: 'cve', cveId: upper };
  if (text.toLowerCase().startsWith('cpe:2.3:') && isCpe23(text)) return { kind: 'cpe', cpe: text };
  return { kind: 'text', query: text };
}
