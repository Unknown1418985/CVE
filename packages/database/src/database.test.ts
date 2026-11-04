import { describe, expect, it } from 'vitest';

import {
  assertServiceOwnsDatabase,
  parseDatabaseUrl,
  pingDatabase,
  redactDatabaseUrl,
  serviceDatabaseName,
  type QueryableDatabaseClient,
} from './index.js';

const url = 'postgresql://cve_service:s3cr%40t@postgres:5432/cve_service?schema=public';

describe('parseDatabaseUrl', () => {
  it('extracts connection info without the password', () => {
    const info = parseDatabaseUrl(url);
    expect(info).toEqual({
      host: 'postgres',
      port: 5432,
      database: 'cve_service',
      user: 'cve_service',
      schema: 'public',
    });
    expect(JSON.stringify(info)).not.toContain('s3cr');
  });

  it('rejects other protocols and missing parts', () => {
    expect(() => parseDatabaseUrl('mysql://u@h/db')).toThrow(/protocol/);
    expect(() => parseDatabaseUrl('postgresql://u@h')).toThrow(/database name/);
    expect(() => parseDatabaseUrl('not a url')).toThrow(/valid URL/);
  });
});

describe('redactDatabaseUrl', () => {
  it('masks the password', () => {
    expect(redactDatabaseUrl(url)).not.toContain('s3cr');
    expect(redactDatabaseUrl(url)).toContain('****');
  });
});

describe('service database ownership', () => {
  it('derives database names from service names', () => {
    expect(serviceDatabaseName('cve-service')).toBe('cve_service');
    expect(() => serviceDatabaseName('../etc')).toThrow();
  });

  it('rejects connections to another service database', () => {
    expect(() => {
      assertServiceOwnsDatabase('cve-service', url);
    }).not.toThrow();
    expect(() => {
      assertServiceOwnsDatabase('poc-service', url);
    }).toThrow(/poc_service/);
  });
});

describe('pingDatabase', () => {
  const client = (fail: boolean): QueryableDatabaseClient => ({
    $connect: () => Promise.resolve(),
    $disconnect: () => Promise.resolve(),
    $queryRawUnsafe: () => (fail ? Promise.reject(new Error('down')) : Promise.resolve([1])),
  });

  it('reports success and failure without throwing', async () => {
    await expect(pingDatabase(client(false))).resolves.toMatchObject({ ok: true });
    await expect(pingDatabase(client(true))).resolves.toMatchObject({ ok: false, error: 'down' });
  });
});
