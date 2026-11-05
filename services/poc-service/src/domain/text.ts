import { validateCveId } from '@cve/contracts';

/**
 * Text written by repository owners (names, descriptions, topics, file names) is untrusted. It is
 * stored and displayed only after these normalisations and is never interpreted.
 */

// C0/C1 controls except tab and newline, bidirectional overrides and isolates (Trojan Source
// style spoofing), zero-width characters and the BOM.
const UNSAFE_CHARACTERS =
  // eslint-disable-next-line no-control-regex -- removing control characters is the purpose
  /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g;

/** Removes unsafe characters, collapses whitespace and truncates to `max` characters. */
export function sanitizeText(input: string | null | undefined, max: number): string | null {
  if (input === null || input === undefined) return null;
  const cleaned = input.normalize('NFC').replace(UNSAFE_CHARACTERS, '').replace(/\s+/g, ' ').trim();
  if (cleaned === '') return null;
  return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned;
}

/** Like `sanitizeText` but keeps the value as one token (paths, names). */
export function sanitizePath(input: string, max = 1_024): string {
  const cleaned = input.normalize('NFC').replace(UNSAFE_CHARACTERS, '');
  return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned;
}

/**
 * CVE IDs as they appear in repository names and texts: `CVE-2024-1234`, `cve_2024_1234`,
 * `CVE 2024 1234`, `CVE2024-1234`. The ID must not be glued to other letters or digits.
 */
const CVE_MENTION = /(?<![A-Za-z0-9])CVE[-_ ]?(\d{4})[-_ ](\d{4,7})(?!\d)/gi;

export interface CveMention {
  readonly cveId: string;
  /** Offset of the match in the text. */
  readonly index: number;
  readonly length: number;
}

/** Finds valid CVE IDs in a text (normalised to `CVE-YYYY-NNNN`), in order of appearance. */
export function findCveMentions(text: string, now: Date = new Date()): CveMention[] {
  const mentions: CveMention[] = [];
  for (const match of text.matchAll(CVE_MENTION)) {
    const result = validateCveId(`CVE-${match[1] ?? ''}-${match[2] ?? ''}`, now);
    if (result.ok) {
      mentions.push({ cveId: result.cveId, index: match.index, length: match[0].length });
    }
  }
  return mentions;
}

export function distinctCveIds(text: string, now?: Date): string[] {
  return [...new Set(findCveMentions(text, now).map((mention) => mention.cveId))];
}

/** A short excerpt around a match, for the evidence shown to analysts. */
export function excerpt(text: string, index: number, length: number, radius = 60): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + length + radius);
  return `${start > 0 ? '…' : ''}${text.slice(start, end)}${end < text.length ? '…' : ''}`;
}
