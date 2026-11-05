const DAY_MS = 86_400_000;

export interface ScanTarget {
  readonly inKev: boolean;
  readonly epssScore: number | null;
  readonly publishedAt: Date | null;
}

/**
 * When a tracked CVE is searched again. PoCs appear mostly in the first weeks after
 * publication and for CVEs that are exploited (KEV) or likely to be (EPSS).
 */
export function nextScanDelayMs(target: ScanTarget, now: Date): number {
  if (target.inKev || (target.epssScore ?? 0) >= 0.1) return DAY_MS;
  const ageMs =
    target.publishedAt === null ? Infinity : now.getTime() - target.publishedAt.getTime();
  if (ageMs <= 30 * DAY_MS) return 2 * DAY_MS;
  if (ageMs <= 365 * DAY_MS) return 14 * DAY_MS;
  return 60 * DAY_MS;
}
