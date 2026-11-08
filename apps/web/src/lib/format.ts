const dateFormatter = new Intl.DateTimeFormat('en-US', {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  timeZone: 'UTC',
});
const dateTimeFormatter = new Intl.DateTimeFormat('en-US', {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  hour12: false,
  timeZone: 'UTC',
});
const numberFormatter = new Intl.NumberFormat('en-US');

function toDate(value: string | Date): Date | null {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Dates are stored and shown in UTC (CLAUDE.md §11). */
export function formatDate(value: string | Date | null | undefined): string {
  if (value === null || value === undefined) return '—';
  const date = toDate(value);
  return date === null ? '—' : dateFormatter.format(date);
}

export function formatDateTime(value: string | Date | null | undefined): string {
  if (value === null || value === undefined) return '—';
  const date = toDate(value);
  return date === null ? '—' : `${dateTimeFormatter.format(date)} UTC`;
}

export function formatRelative(
  value: string | Date | null | undefined,
  now: Date = new Date(),
): string {
  if (value === null || value === undefined) return '—';
  const date = toDate(value);
  if (date === null) return '—';
  const seconds = Math.round((date.getTime() - now.getTime()) / 1000);
  const abs = Math.abs(seconds);
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['year', 31_536_000],
    ['month', 2_592_000],
    ['day', 86_400],
    ['hour', 3_600],
    ['minute', 60],
  ];
  const formatter = new Intl.RelativeTimeFormat('en-US', { numeric: 'auto' });
  for (const [unit, size] of units) {
    if (abs >= size) return formatter.format(Math.round(seconds / size), unit);
  }
  return formatter.format(seconds, 'second');
}

export function formatNumber(value: number | null | undefined): string {
  return value === null || value === undefined ? '—' : numberFormatter.format(value);
}

/** Probability (0–1) as a percentage, e.g. EPSS. */
export function formatPercent(value: number | null | undefined, digits = 2): string {
  if (value === null || value === undefined) return '—';
  return `${(value * 100).toFixed(digits)}%`;
}

export function formatScore(value: number | null | undefined): string {
  return value === null || value === undefined ? '—' : value.toFixed(1);
}

export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  if (value < 1024) return `${value} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unit] ?? 'TiB'}`;
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes} min ${Math.round(seconds % 60)} s`;
}

/** `in-review` → `In review`, `proof-of-concept` → `Proof of concept`. */
export function humanize(value: string): string {
  const text = value.replaceAll(/[-_]/g, ' ');
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function shortHash(value: string, length = 12): string {
  return value.length <= length ? value : `${value.slice(0, length)}…`;
}
