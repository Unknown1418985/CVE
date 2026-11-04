/** Subset of `docker compose ps --format json` used to decide whether the stack is ready. */
export interface ContainerStatus {
  readonly Service: string;
  readonly State: string;
  readonly Health: string;
  readonly ExitCode: number;
}

export type StackVerdict =
  | { readonly kind: 'ready' }
  | { readonly kind: 'waiting'; readonly pending: readonly string[] }
  | { readonly kind: 'failed'; readonly reason: string };

/** Parses both the JSON-array and the newline-delimited output formats of `docker compose ps`. */
export function parseComposePs(output: string): ContainerStatus[] {
  const trimmed = output.trim();
  if (trimmed === '') return [];
  const raw: unknown = trimmed.startsWith('[')
    ? JSON.parse(trimmed)
    : trimmed.split('\n').map((line) => JSON.parse(line) as unknown);
  if (!Array.isArray(raw)) throw new Error('Unexpected docker compose ps output');
  const text = (value: unknown, fallback: string) => (typeof value === 'string' ? value : fallback);
  return raw.map((entry: unknown) => {
    const item = (typeof entry === 'object' && entry !== null ? entry : {}) as Record<
      string,
      unknown
    >;
    return {
      Service: text(item['Service'], '?'),
      State: text(item['State'], ''),
      Health: text(item['Health'], ''),
      ExitCode: typeof item['ExitCode'] === 'number' ? item['ExitCode'] : 0,
    };
  });
}

/**
 * One-shot jobs must have exited with 0; every other container must be running and, when it
 * defines a health check, healthy. A non-zero exit fails immediately.
 */
export function evaluateStack(containers: readonly ContainerStatus[]): StackVerdict {
  if (containers.length === 0) return { kind: 'failed', reason: 'no containers found' };
  const pending: string[] = [];
  for (const container of containers) {
    if (container.State === 'exited' || container.State === 'dead') {
      if (container.ExitCode !== 0) {
        return {
          kind: 'failed',
          reason: `${container.Service} exited with code ${container.ExitCode}`,
        };
      }
      continue;
    }
    if (container.State !== 'running') {
      pending.push(`${container.Service} (${container.State})`);
    } else if (container.Health !== '' && container.Health !== 'healthy') {
      pending.push(`${container.Service} (${container.Health})`);
    }
  }
  return pending.length === 0 ? { kind: 'ready' } : { kind: 'waiting', pending };
}
