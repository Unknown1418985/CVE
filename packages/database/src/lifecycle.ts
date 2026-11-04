/**
 * Minimal surface of a Prisma client used for lifecycle and readiness checks.
 * Each service generates its own Prisma client; this interface keeps this package
 * independent of any one service's generated client.
 */
export interface QueryableDatabaseClient {
  $connect(): Promise<void>;
  $disconnect(): Promise<void>;
  $queryRawUnsafe(query: string): Promise<unknown>;
}

export interface DatabasePingResult {
  readonly ok: boolean;
  readonly latencyMs: number;
  readonly error?: string;
}

/** Runs `SELECT 1` and measures latency. Never throws. */
export async function pingDatabase(client: QueryableDatabaseClient): Promise<DatabasePingResult> {
  const started = performance.now();
  try {
    await client.$queryRawUnsafe('SELECT 1');
    return { ok: true, latencyMs: Math.round(performance.now() - started) };
  } catch (error) {
    return {
      ok: false,
      latencyMs: Math.round(performance.now() - started),
      error: error instanceof Error ? error.message : 'Unknown database error',
    };
  }
}
