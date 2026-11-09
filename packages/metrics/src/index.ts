import {
  Counter,
  Gauge,
  Histogram,
  Registry,
  type CounterConfiguration,
  type GaugeConfiguration,
  type HistogramConfiguration,
  type Metric,
} from 'prom-client';

/**
 * Process-wide registry for instruments created by shared platform packages (messaging, jobs,
 * auth) and by service domain code. The service bootstrap (`@cve/shared`) serves it next to the
 * per-process HTTP and runtime metrics on the internal metrics port.
 *
 * Instruments are created lazily and idempotently: asking twice for the same name returns the
 * same instrument, so constructing several consumers, workers or test apps in one process never
 * fails with "metric already registered".
 */
export const platformRegistry = new Registry();

export type { Counter, Gauge, Histogram, Registry } from 'prom-client';

type Ctor<T> = abstract new (...args: never[]) => T;

function existing<T extends Metric>(name: string, kind: Ctor<T>): T | undefined {
  const metric = platformRegistry.getSingleMetric(name);
  if (metric === undefined) return undefined;
  if (!(metric instanceof kind)) {
    throw new Error(`Metric ${name} is already registered with a different type`);
  }
  return metric;
}

export function counter<L extends string>(
  config: Omit<CounterConfiguration<L>, 'registers'>,
): Counter<L> {
  return (
    existing<Counter<L>>(config.name, Counter) ??
    new Counter<L>({ ...config, registers: [platformRegistry] })
  );
}

export function histogram<L extends string>(
  config: Omit<HistogramConfiguration<L>, 'registers'>,
): Histogram<L> {
  return (
    existing<Histogram<L>>(config.name, Histogram) ??
    new Histogram<L>({ ...config, registers: [platformRegistry] })
  );
}

export function gauge<L extends string>(
  config: Omit<GaugeConfiguration<L>, 'registers'>,
): Gauge<L> {
  return (
    existing<Gauge<L>>(config.name, Gauge) ??
    new Gauge<L>({ ...config, registers: [platformRegistry] })
  );
}

/** Labels added to every platform instrument (the service name and version). */
export function setPlatformDefaultLabels(labels: Readonly<Record<string, string>>): void {
  platformRegistry.setDefaultLabels({ ...labels });
}

/** Duration buckets (seconds) for work that ranges from milliseconds to minutes. */
export const WORK_DURATION_BUCKETS = [
  0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600,
] as const;

/**
 * Keeps a label value bounded and log-safe: unknown or oversized values collapse to `other`
 * so an attacker-influenced string can never explode label cardinality.
 */
export function boundedLabel(value: string | undefined, allowed?: ReadonlySet<string>): string {
  if (value === undefined || value === '') return 'unknown';
  if (allowed !== undefined) return allowed.has(value) ? value : 'other';
  return /^[A-Za-z0-9_.:-]{1,64}$/.test(value) ? value : 'other';
}
