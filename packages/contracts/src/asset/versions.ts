/**
 * Version comparison for affected-version ranges.
 *
 * Vendors use many version schemes (semver, dotted numbers, dates, `1.2p3`, `2.4.0-rc1`), and no
 * single ordering is correct for all of them. This comparator implements the common subset that
 * NVD configurations rely on, and reports `null` ("cannot tell") instead of guessing:
 *
 * - A leading `v` and SemVer build metadata (`+…`) are ignored.
 * - The version is split into numeric and alphabetic segments (`1.10.0-rc2` → 1, 10, 0, rc, 2).
 * - Numeric segments compare numerically, alphabetic segments case-insensitively.
 * - Missing trailing segments count as `0` against numbers (`1.0` = `1.0.0`) and as a release
 *   against letters, so pre-releases sort first (`1.0-rc1` < `1.0`).
 * - A number is greater than letters at the same position (`1.0.1` > `1.0.beta`).
 * - Wildcards (`*`, `-`), empty strings and anything with whitespace are not comparable.
 */

type Segment =
  | { readonly kind: 'number'; readonly value: bigint }
  | { readonly kind: 'text'; readonly value: string };

const MAX_VERSION_LENGTH = 128;

function segments(version: string): Segment[] | null {
  let text = version.trim();
  if (text === '' || text === '*' || text === '-' || text.length > MAX_VERSION_LENGTH) return null;
  if (/\s/.test(text)) return null;
  if (/^v\d/i.test(text)) text = text.slice(1);
  const plus = text.indexOf('+');
  if (plus > 0) text = text.slice(0, plus);
  const tokens = text.toLowerCase().match(/\d+|[a-z]+/g);
  if (!tokens) return null;
  return tokens.map((token) =>
    /^\d/.test(token) ? { kind: 'number', value: BigInt(token) } : { kind: 'text', value: token },
  );
}

/** -1, 0 or 1 when the versions are comparable; `null` otherwise. */
export function compareVersions(a: string, b: string): -1 | 0 | 1 | null {
  const left = segments(a);
  const right = segments(b);
  if (left === null || right === null) return null;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const l = left[index];
    const r = right[index];
    if (l === undefined || r === undefined) {
      const present = l ?? r;
      if (present === undefined) break;
      // Missing vs number: missing is 0. Missing vs text: the text is a pre-release (lower).
      let cmp: -1 | 0 | 1;
      if (present.kind === 'number') cmp = present.value === 0n ? 0 : -1;
      else cmp = 1;
      if (cmp === 0) continue;
      return l === undefined ? cmp : (-cmp as -1 | 1);
    }
    if (l.kind !== r.kind) return l.kind === 'number' ? 1 : -1;
    if (l.value !== r.value) return l.value < r.value ? -1 : 1;
  }
  return 0;
}

/** Bounds of an affected-version range, as stored per association. */
export interface VersionBounds {
  readonly version?: string | null | undefined;
  readonly versionStartIncluding?: string | null | undefined;
  readonly versionStartExcluding?: string | null | undefined;
  readonly versionEndIncluding?: string | null | undefined;
  readonly versionEndExcluding?: string | null | undefined;
}

/**
 * Whether `version` falls inside the range: `true`, `false`, or `null` when a bound is not
 * comparable with the version. A range without any bound covers every version.
 */
export function rangeContains(range: VersionBounds, version: string): boolean | null {
  const exact = range.version ?? undefined;
  if (exact !== undefined && exact !== '*') {
    if (exact === '-') return null;
    if (exact.toLowerCase() === version.trim().toLowerCase()) return true;
    const cmp = compareVersions(version, exact);
    return cmp === null ? null : cmp === 0;
  }
  const checks: [string | null | undefined, (cmp: -1 | 0 | 1) => boolean][] = [
    [range.versionStartIncluding, (cmp) => cmp >= 0],
    [range.versionStartExcluding, (cmp) => cmp > 0],
    [range.versionEndIncluding, (cmp) => cmp <= 0],
    [range.versionEndExcluding, (cmp) => cmp < 0],
  ];
  let unknown = false;
  for (const [bound, accept] of checks) {
    if (bound === null || bound === undefined) continue;
    const cmp = compareVersions(version, bound);
    if (cmp === null) {
      unknown = true;
      continue;
    }
    if (!accept(cmp)) return false;
  }
  return unknown ? null : true;
}
