/**
 * CVSS vector parsing and validation for v3.1 and v4.0, base score calculation for v3.1 and the
 * qualitative severity scale shared by both versions.
 *
 * - CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document (sections 5, 7.1, 7.4, A.2)
 * - CVSS v4.0: https://www.first.org/cvss/v4.0/specification-document (sections 3–5, 7)
 *
 * The CVSS v4.0 score is defined by FIRST's MacroVector lookup tables rather than a formula, so
 * it is not computed here: v4.0 scores are taken from the source and checked for range only.
 */

export const CVSS_VERSIONS = ['3.1', '4.0'] as const;
export type CvssVersion = (typeof CVSS_VERSIONS)[number];

export const SEVERITIES = ['none', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Overall severity of a CVE record; `unknown` when no CVSS metric is known. */
export const RECORD_SEVERITIES = [...SEVERITIES, 'unknown'] as const;
export type RecordSeverity = (typeof RECORD_SEVERITIES)[number];

type MetricDefinitions = Readonly<Record<string, readonly string[]>>;

const V31_BASE: MetricDefinitions = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'R'],
  S: ['U', 'C'],
  C: ['H', 'L', 'N'],
  I: ['H', 'L', 'N'],
  A: ['H', 'L', 'N'],
};

const V31_OPTIONAL: MetricDefinitions = {
  E: ['X', 'U', 'P', 'F', 'H'],
  RL: ['X', 'O', 'T', 'W', 'U'],
  RC: ['X', 'U', 'R', 'C'],
  CR: ['X', 'L', 'M', 'H'],
  IR: ['X', 'L', 'M', 'H'],
  AR: ['X', 'L', 'M', 'H'],
  MAV: ['X', 'N', 'A', 'L', 'P'],
  MAC: ['X', 'L', 'H'],
  MPR: ['X', 'N', 'L', 'H'],
  MUI: ['X', 'N', 'R'],
  MS: ['X', 'U', 'C'],
  MC: ['X', 'N', 'L', 'H'],
  MI: ['X', 'N', 'L', 'H'],
  MA: ['X', 'N', 'L', 'H'],
};

const V40_BASE: MetricDefinitions = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  AT: ['N', 'P'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'P', 'A'],
  VC: ['H', 'L', 'N'],
  VI: ['H', 'L', 'N'],
  VA: ['H', 'L', 'N'],
  SC: ['H', 'L', 'N'],
  SI: ['H', 'L', 'N'],
  SA: ['H', 'L', 'N'],
};

const V40_OPTIONAL: MetricDefinitions = {
  E: ['X', 'A', 'P', 'U'],
  CR: ['X', 'H', 'M', 'L'],
  IR: ['X', 'H', 'M', 'L'],
  AR: ['X', 'H', 'M', 'L'],
  MAV: ['X', 'N', 'A', 'L', 'P'],
  MAC: ['X', 'L', 'H'],
  MAT: ['X', 'N', 'P'],
  MPR: ['X', 'N', 'L', 'H'],
  MUI: ['X', 'N', 'P', 'A'],
  MVC: ['X', 'H', 'L', 'N'],
  MVI: ['X', 'H', 'L', 'N'],
  MVA: ['X', 'H', 'L', 'N'],
  MSC: ['X', 'H', 'L', 'N'],
  MSI: ['X', 'S', 'H', 'L', 'N'],
  MSA: ['X', 'S', 'H', 'L', 'N'],
  S: ['X', 'N', 'P'],
  AU: ['X', 'N', 'Y'],
  R: ['X', 'A', 'U', 'I'],
  V: ['X', 'D', 'C'],
  RE: ['X', 'L', 'M', 'H'],
  U: ['X', 'Clear', 'Green', 'Amber', 'Red'],
};

interface VersionSpec {
  readonly prefix: string;
  readonly base: MetricDefinitions;
  readonly optional: MetricDefinitions;
  /** v4.0 requires metrics in specification order; v3.1 only recommends it. */
  readonly strictOrder: boolean;
}

const SPECS: Readonly<Record<CvssVersion, VersionSpec>> = {
  '3.1': { prefix: 'CVSS:3.1', base: V31_BASE, optional: V31_OPTIONAL, strictOrder: false },
  '4.0': { prefix: 'CVSS:4.0', base: V40_BASE, optional: V40_OPTIONAL, strictOrder: true },
};

export interface ParsedCvssVector {
  readonly version: CvssVersion;
  /** Canonical vector: prefix, then metrics in specification order. */
  readonly vectorString: string;
  /** Every metric present in the vector, keyed by abbreviation. */
  readonly metrics: Readonly<Record<string, string>>;
}

export type CvssParseResult =
  | { readonly ok: true; readonly vector: ParsedCvssVector }
  | { readonly ok: false; readonly error: string };

/** Longest vector accepted; a full v4.0 vector with every optional metric is ~210 characters. */
export const MAX_CVSS_VECTOR_LENGTH = 512;

/** Parses and validates a CVSS vector string of the given version (or detects it). */
export function parseCvssVector(input: string, expected?: CvssVersion): CvssParseResult {
  if (input.length > MAX_CVSS_VECTOR_LENGTH) return { ok: false, error: 'vector is too long' };
  const [prefix, ...segments] = input.trim().split('/');
  const version = CVSS_VERSIONS.find((candidate) => SPECS[candidate].prefix === prefix);
  if (version === undefined) {
    return { ok: false, error: 'vector must start with CVSS:3.1/ or CVSS:4.0/' };
  }
  if (expected !== undefined && version !== expected) {
    return { ok: false, error: `vector is CVSS ${version}, expected CVSS ${expected}` };
  }
  const spec = SPECS[version];
  const order = [...Object.keys(spec.base), ...Object.keys(spec.optional)];
  const metrics: Record<string, string> = {};
  let lastIndex = -1;
  for (const segment of segments) {
    const [key = '', value, ...rest] = segment.split(':');
    if (value === undefined || rest.length > 0 || key === '' || value === '') {
      return { ok: false, error: `malformed metric "${segment}"` };
    }
    const allowed = spec.base[key] ?? spec.optional[key];
    if (allowed === undefined) return { ok: false, error: `unknown metric "${key}"` };
    if (Object.hasOwn(metrics, key)) return { ok: false, error: `duplicate metric "${key}"` };
    if (!allowed.includes(value)) {
      return { ok: false, error: `invalid value "${value}" for metric "${key}"` };
    }
    const index = order.indexOf(key);
    if (spec.strictOrder && index < lastIndex) {
      return { ok: false, error: `metric "${key}" is out of order` };
    }
    lastIndex = Math.max(lastIndex, index);
    metrics[key] = value;
  }
  const missing = Object.keys(spec.base).filter((key) => !Object.hasOwn(metrics, key));
  if (missing.length > 0) {
    return { ok: false, error: `missing base metrics: ${missing.join(', ')}` };
  }
  const canonical = order.filter((key) => Object.hasOwn(metrics, key));
  return {
    ok: true,
    vector: {
      version,
      vectorString: [spec.prefix, ...canonical.map((key) => `${key}:${metrics[key] ?? ''}`)].join(
        '/',
      ),
      metrics: Object.fromEntries(canonical.map((key) => [key, metrics[key] ?? ''])),
    },
  };
}

/** CVSS v3.1 Roundup (Appendix A): smallest one-decimal number ≥ input, float-safe. */
export function roundUp31(value: number): number {
  const integer = Math.round(value * 100_000);
  return integer % 10_000 === 0 ? integer / 100_000 : (Math.floor(integer / 10_000) + 1) / 10;
}

const WEIGHTS_31 = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
} as const;

function weight(table: Readonly<Record<string, number>>, key: string | undefined): number {
  const value = key === undefined ? undefined : table[key];
  if (value === undefined) throw new Error(`no CVSS weight for "${String(key)}"`);
  return value;
}

/** CVSS v3.1 base score (specification section 7.1) of a parsed v3.1 vector. */
export function cvss31BaseScore(vector: ParsedCvssVector): number {
  if (vector.version !== '3.1') throw new Error('cvss31BaseScore requires a CVSS 3.1 vector');
  const m = vector.metrics;
  const changed = m['S'] === 'C';
  const iss =
    1 -
    (1 - weight(WEIGHTS_31.CIA, m['C'])) *
      (1 - weight(WEIGHTS_31.CIA, m['I'])) *
      (1 - weight(WEIGHTS_31.CIA, m['A']));
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const exploitability =
    8.22 *
    weight(WEIGHTS_31.AV, m['AV']) *
    weight(WEIGHTS_31.AC, m['AC']) *
    weight(changed ? WEIGHTS_31.PR.C : WEIGHTS_31.PR.U, m['PR']) *
    weight(WEIGHTS_31.UI, m['UI']);
  if (impact <= 0) return 0;
  return roundUp31(Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10));
}

/** Qualitative severity rating scale (identical in CVSS v3.1 section 5 and v4.0 section 7). */
export function severityForScore(score: number): Severity {
  if (!Number.isFinite(score) || score < 0 || score > 10) {
    throw new Error('CVSS scores range from 0.0 to 10.0');
  }
  if (score === 0) return 'none';
  if (score < 4) return 'low';
  if (score < 7) return 'medium';
  if (score < 9) return 'high';
  return 'critical';
}

/** Whether `score` is a valid CVSS score: 0.0–10.0 with at most one decimal. */
export function isCvssScore(score: number): boolean {
  return (
    Number.isFinite(score) &&
    score >= 0 &&
    score <= 10 &&
    Math.abs(Math.round(score * 10) - score * 10) < 1e-9
  );
}
