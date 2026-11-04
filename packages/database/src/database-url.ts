export interface DatabaseConnectionInfo {
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly user: string;
  readonly schema: string | undefined;
}

const POSTGRES_PROTOCOLS = new Set(['postgres:', 'postgresql:']);
const DEFAULT_POSTGRES_PORT = 5432;

/** Parses a PostgreSQL connection URL. The password is intentionally not returned. */
export function parseDatabaseUrl(url: string): DatabaseConnectionInfo {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('DATABASE_URL is not a valid URL');
  }
  if (!POSTGRES_PROTOCOLS.has(parsed.protocol)) {
    throw new Error('DATABASE_URL must use the postgres:// or postgresql:// protocol');
  }
  const database = decodeURIComponent(parsed.pathname.replace(/^\//, ''));
  if (database.length === 0) {
    throw new Error('DATABASE_URL must include a database name');
  }
  if (parsed.username.length === 0) {
    throw new Error('DATABASE_URL must include a user');
  }
  return {
    host: parsed.hostname,
    port: parsed.port === '' ? DEFAULT_POSTGRES_PORT : Number(parsed.port),
    database,
    user: decodeURIComponent(parsed.username),
    schema: parsed.searchParams.get('schema') ?? undefined,
  };
}

/** Returns the URL with its password masked, safe for logs and error messages. */
export function redactDatabaseUrl(url: string): string {
  const parsed = new URL(url);
  if (parsed.password !== '') {
    parsed.password = '****';
  }
  return parsed.toString();
}

/**
 * Enforces database ownership: every service connects to a database named after itself
 * (e.g. `cve-service` → `cve_service`) with a role of the same name.
 */
export function serviceDatabaseName(serviceName: string): string {
  if (!/^[a-z][a-z0-9-]*$/.test(serviceName)) {
    throw new Error(`Invalid service name for database: ${serviceName}`);
  }
  return serviceName.replaceAll('-', '_');
}

export function assertServiceOwnsDatabase(serviceName: string, url: string): void {
  const expected = serviceDatabaseName(serviceName);
  const info = parseDatabaseUrl(url);
  if (info.database !== expected) {
    throw new Error(
      `${serviceName} must connect to its own database "${expected}", got "${info.database}"`,
    );
  }
  if (info.user !== expected) {
    throw new Error(`${serviceName} must connect with its own role "${expected}"`);
  }
}
