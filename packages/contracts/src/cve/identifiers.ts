import { z } from 'zod';

/**
 * CVE identifier syntax (MITRE, since 2014): `CVE-YYYY-NNNN…`. The sequence has at least four
 * digits; sequences longer than four digits never start with a zero.
 */
export const CVE_ID_PATTERN = /^CVE-(\d{4})-(\d{4,19})$/;

/** The first CVE identifiers were issued for 1999. */
export const FIRST_CVE_YEAR = 1999;

export interface CveIdParts {
  readonly year: number;
  readonly sequence: bigint;
}

export type CveIdValidation =
  | { readonly ok: true; readonly cveId: string; readonly parts: CveIdParts }
  | { readonly ok: false; readonly reason: string };

/**
 * Normalises (trim, upper-case) and validates a CVE identifier. `now` bounds the year: IDs are
 * reserved in the current year, one year of slack covers time zones and early reservations.
 */
export function validateCveId(input: string, now: Date = new Date()): CveIdValidation {
  const cveId = input.trim().toUpperCase();
  const match = CVE_ID_PATTERN.exec(cveId);
  if (!match) return { ok: false, reason: 'must match CVE-YYYY-NNNN (at least four digits)' };
  const [, yearText = '', sequenceText = ''] = match;
  const year = Number(yearText);
  if (year < FIRST_CVE_YEAR || year > now.getUTCFullYear() + 1) {
    return { ok: false, reason: `year must be between ${FIRST_CVE_YEAR} and next year` };
  }
  if (sequenceText.length > 4 && sequenceText.startsWith('0')) {
    return { ok: false, reason: 'sequences longer than four digits must not start with 0' };
  }
  const sequence = BigInt(sequenceText);
  if (sequence === 0n) return { ok: false, reason: 'sequence must not be zero' };
  return { ok: true, cveId, parts: { year, sequence } };
}

/** Parses a known-valid CVE identifier into year and sequence. Throws on invalid input. */
export function parseCveId(input: string): CveIdParts {
  const result = validateCveId(input);
  if (!result.ok) throw new Error(`Invalid CVE identifier: ${result.reason}`);
  return result.parts;
}

/** Normalised, validated CVE identifier (accepts lower case and surrounding whitespace). */
export const cveIdSchema = z
  .string()
  .max(32)
  .transform((value, ctx) => {
    const result = validateCveId(value);
    if (!result.ok) {
      ctx.addIssue({ code: 'custom', message: `invalid CVE ID: ${result.reason}` });
      return z.NEVER;
    }
    return result.cveId;
  });

/** CWE identifiers as used by NVD, including its two placeholder values. */
export const CWE_PLACEHOLDERS = ['NVD-CWE-noinfo', 'NVD-CWE-Other'] as const;
const CWE_ID_PATTERN = /^CWE-[1-9]\d{0,5}$/;

export function normalizeCweId(input: string): string | null {
  const trimmed = input.trim();
  const placeholder = CWE_PLACEHOLDERS.find(
    (value) => value.toLowerCase() === trimmed.toLowerCase(),
  );
  if (placeholder) return placeholder;
  const upper = trimmed.toUpperCase();
  return CWE_ID_PATTERN.test(upper) ? upper : null;
}

export const cweIdSchema = z
  .string()
  .max(32)
  .transform((value, ctx) => {
    const normalized = normalizeCweId(value);
    if (normalized === null) {
      ctx.addIssue({
        code: 'custom',
        message: 'invalid CWE ID: expected CWE-<number>, NVD-CWE-noinfo or NVD-CWE-Other',
      });
      return z.NEVER;
    }
    return normalized;
  });

/** Splits a CPE 2.3 formatted string on colons that are not escaped with a backslash. */
function splitCpe(value: string): string[] {
  const parts: string[] = [];
  let current = '';
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index] ?? '';
    if (char === '\\') {
      current += char + (value[index + 1] ?? '');
      index += 1;
    } else if (char === ':') {
      parts.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  parts.push(current);
  return parts;
}

const CPE_COMPONENT_PATTERN = /^(?:\*|-|(?:[A-Za-z0-9._~*?-]|\\[!-/:-@[-`{-~])+)$/;

/** Validates a CPE 2.3 formatted string (NISTIR 7695): 13 components, part `a`, `o` or `h`. */
export function isCpe23(value: string): boolean {
  if (value.length > 512) return false;
  const parts = splitCpe(value);
  if (parts.length !== 13 || parts[0] !== 'cpe' || parts[1] !== '2.3') return false;
  if (!['a', 'o', 'h', '*', '-'].includes(parts[2] ?? '')) return false;
  return parts.slice(3).every((part) => CPE_COMPONENT_PATTERN.test(part));
}

export const cpe23Schema = z
  .string()
  .trim()
  .max(512)
  .refine(isCpe23, { message: 'must be a CPE 2.3 formatted string (cpe:2.3:part:vendor:…)' });

/** The eleven attribute components of a CPE 2.3 formatted string, still in escaped form. */
export interface Cpe23Parts {
  readonly part: string;
  readonly vendor: string;
  readonly product: string;
  readonly version: string;
  readonly update: string;
  readonly edition: string;
  readonly language: string;
  readonly swEdition: string;
  readonly targetSw: string;
  readonly targetHw: string;
  readonly other: string;
}

/**
 * Splits a valid CPE 2.3 formatted string into its components. Components are lower-cased: CPE
 * name matching is case-insensitive (NISTIR 7696). Returns `null` for invalid input.
 */
export function parseCpe23(value: string): Cpe23Parts | null {
  const trimmed = value.trim();
  if (!isCpe23(trimmed)) return null;
  const [
    ,
    ,
    part,
    vendor,
    product,
    version,
    update,
    edition,
    language,
    swEdition,
    targetSw,
    targetHw,
    other,
  ] = splitCpe(trimmed.toLowerCase());
  return {
    part: part ?? '*',
    vendor: vendor ?? '*',
    product: product ?? '*',
    version: version ?? '*',
    update: update ?? '*',
    edition: edition ?? '*',
    language: language ?? '*',
    swEdition: swEdition ?? '*',
    targetSw: targetSw ?? '*',
    targetHw: targetHw ?? '*',
    other: other ?? '*',
  };
}

/** Formats components back into a CPE 2.3 formatted string. */
export function formatCpe23(parts: Cpe23Parts): string {
  return [
    'cpe',
    '2.3',
    parts.part,
    parts.vendor,
    parts.product,
    parts.version,
    parts.update,
    parts.edition,
    parts.language,
    parts.swEdition,
    parts.targetSw,
    parts.targetHw,
    parts.other,
  ].join(':');
}

/** CPE 2.3 name of the product itself: every component after `product` is a wildcard. */
export function cpe23ProductName(parts: Pick<Cpe23Parts, 'part' | 'vendor' | 'product'>): string {
  return `cpe:2.3:${parts.part}:${parts.vendor}:${parts.product}:*:*:*:*:*:*:*:*`;
}
