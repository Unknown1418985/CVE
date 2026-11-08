/**
 * Client-side exports of data the APIs returned. Everything here is pure so it can be tested
 * without a browser.
 */

export type CellValue = string | number | boolean | null | undefined | readonly string[];

export interface ExportColumn<T> {
  readonly header: string;
  readonly value: (row: T) => CellValue;
}

const BOM = String.fromCharCode(0xfeff);

/** Characters that make spreadsheet applications evaluate a cell as a formula. */
const FORMULA_PREFIX = /^[=+\-@\t\r]/;

function cellText(value: CellValue): string {
  if (value === null || value === undefined) return '';
  if (Array.isArray(value)) return value.join('; ');
  return String(value);
}

/**
 * One CSV field (RFC 4180). Text that a spreadsheet would run as a formula is prefixed with an
 * apostrophe: exported data comes from external sources (CVE descriptions, repository names)
 * and must not become executable in the analyst's spreadsheet (CSV injection).
 */
export function csvField(value: CellValue): string {
  let text = cellText(value);
  if (typeof value === 'string' && FORMULA_PREFIX.test(text)) text = `'${text}`;
  if (Array.isArray(value) && FORMULA_PREFIX.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) || text !== text.trim() ? `"${text.replaceAll('"', '""')}"` : text;
}

export function toCsv<T>(rows: readonly T[], columns: readonly ExportColumn<T>[]): string {
  const lines = [columns.map((column) => csvField(column.header)).join(',')];
  for (const row of rows)
    lines.push(columns.map((column) => csvField(column.value(row))).join(','));
  // CRLF line endings and a BOM so spreadsheet applications detect UTF-8.
  return `${BOM}${lines.join('\r\n')}\r\n`;
}

export function toJson<T>(
  rows: readonly T[],
  columns: readonly ExportColumn<T>[],
  meta: Readonly<Record<string, unknown>>,
): string {
  const data = rows.map((row) =>
    Object.fromEntries(
      columns.map((column) => {
        const value = column.value(row);
        return [column.header, value ?? null];
      }),
    ),
  );
  return `${JSON.stringify({ ...meta, rowCount: rows.length, data }, null, 2)}\n`;
}

/** Safe file name: only letters, digits and dashes, with a UTC timestamp. */
export function exportFileName(
  report: string,
  extension: 'csv' | 'json',
  now: Date = new Date(),
): string {
  const slug =
    report
      .toLowerCase()
      .replaceAll(/[^a-z0-9]+/g, '-')
      .replaceAll(/^-+|-+$/g, '') || 'report';
  const stamp = now.toISOString().slice(0, 19).replaceAll(':', '').replace('T', '-');
  return `${slug}-${stamp}.${extension}`;
}
