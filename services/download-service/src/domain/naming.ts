import { createHash } from 'node:crypto';

/** Control, bidirectional-override and zero-width characters. */
const UNSAFE_CHARACTERS = /[\p{Cc}\p{Cf}  ]/gu;

/**
 * The name a source suggests (Content-Disposition or the last URL segment), reduced to a safe
 * display string. It is metadata only: it never becomes a filesystem path, an object key or the
 * name the platform serves the file under.
 */
export function sanitizeFilename(raw: string | null | undefined): string | null {
  if (raw === null || raw === undefined) return null;
  let name = raw;
  try {
    name = decodeURIComponent(name);
  } catch {
    // Keep the raw text when it is not valid percent-encoding.
  }
  name = name.replace(UNSAFE_CHARACTERS, '');
  // Keep only the last path component, whatever separator the source used.
  name = name.split(/[/\\]/).at(-1) ?? '';
  name = name.trim().replace(/^\.+/, '');
  if (name === '' || name === '.' || name === '..') return null;
  return name.length > 255 ? name.slice(0, 255) : name;
}

/** Parses `filename*=` (RFC 6266/8187) or `filename=` from a Content-Disposition header. */
export function filenameFromContentDisposition(header: string | null): string | null {
  if (header === null) return null;
  const extended = /filename\*\s*=\s*(?:UTF-8|ISO-8859-1)?'[^']*'([^;]+)/i.exec(header);
  if (extended?.[1] !== undefined) return sanitizeFilename(extended[1].trim());
  const quoted = /filename\s*=\s*"((?:[^"\\]|\\.)*)"/i.exec(header);
  if (quoted?.[1] !== undefined) return sanitizeFilename(quoted[1].replace(/\\(.)/g, '$1'));
  const token = /filename\s*=\s*([^;\s]+)/i.exec(header);
  return token?.[1] === undefined ? null : sanitizeFilename(token[1]);
}

export function filenameFromUrl(url: string): string | null {
  try {
    const segment = new URL(url).pathname.split('/').filter((part) => part !== '').at(-1);
    return sanitizeFilename(segment ?? null);
  } catch {
    return null;
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function assertUuid(id: string): void {
  if (!UUID.test(id)) throw new Error('object keys are built from artifact UUIDs only');
}

/** Generated quarantine key: a date partition and the artifact UUID, nothing from the source. */
export function quarantineKey(artifactId: string, at: Date): string {
  assertUuid(artifactId);
  const year = String(at.getUTCFullYear()).padStart(4, '0');
  const month = String(at.getUTCMonth() + 1).padStart(2, '0');
  return `quarantine/${year}/${month}/${artifactId}`;
}

export function releasedKey(artifactId: string): string {
  assertUuid(artifactId);
  return `released/${artifactId}`;
}

export const sha256Hex = (value: string) => createHash('sha256').update(value).digest('hex');
