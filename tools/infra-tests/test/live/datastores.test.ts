import { readFileSync } from 'node:fs';
import { request } from 'node:https';

import {
  CopyObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { BACKEND_SERVICE_NAMES, OBJECT_STORAGE_BUCKETS } from '@cve/contracts';
import { integrationHost, requireEnv } from '@cve/testing/integration';
import pg from 'pg';
import { describe, expect, it } from 'vitest';

import { devPorts } from './mode.js';

const host = integrationHost();
const snake = (service: string) => service.toUpperCase().replaceAll('-', '_');

describe.runIf(devPorts)('PostgreSQL least privilege', () => {
  const client = (user: string, password: string, database: string) =>
    new pg.Client({ host, port: 5432, user, password, database, connectionTimeoutMillis: 5_000 });

  it('lets each service connect to its own database only', async () => {
    for (const service of BACKEND_SERVICE_NAMES) {
      const database = service.replaceAll('-', '_');
      const own = client(database, requireEnv(`${snake(service)}_DB_PASSWORD`), database);
      await own.connect();
      const { rows } = await own.query<{ current_user: string; superuser: string }>(
        "SELECT current_user, current_setting('is_superuser') AS superuser",
      );
      expect(rows[0]).toEqual({ current_user: database, superuser: 'off' });
      await own.end();
    }

    for (const database of ['poc_service', 'keycloak', 'postgres', 'template1']) {
      const intruder = client('cve_service', requireEnv('CVE_SERVICE_DB_PASSWORD'), database);
      await expect(intruder.connect(), database).rejects.toThrow(
        new RegExp(`permission denied for database "${database}"`),
      );
    }
  });

  it('denies role and database creation but allows migrations in the own schema', async () => {
    const cve = client('cve_service', requireEnv('CVE_SERVICE_DB_PASSWORD'), 'cve_service');
    await cve.connect();
    await expect(cve.query('CREATE ROLE intruder')).rejects.toThrow(/permission denied/);
    await expect(cve.query('CREATE DATABASE intruder')).rejects.toThrow(/permission denied/);
    // The service owns its schema and can run migrations in it.
    await cve.query('CREATE TABLE IF NOT EXISTS itest_probe (id uuid PRIMARY KEY)');
    await cve.query('DROP TABLE itest_probe');
    await cve.end();

    const exporter = client(
      'postgres_exporter',
      requireEnv('POSTGRES_EXPORTER_PASSWORD'),
      'postgres',
    );
    await exporter.connect();
    const { rows } = await exporter.query<{ count: string }>(
      'SELECT count(*) FROM pg_stat_activity',
    );
    expect(Number(rows[0]?.count)).toBeGreaterThan(0);
    await exporter.end();
  });

  it('rejects wrong passwords', async () => {
    const wrong = client('cve_service', 'not-the-password', 'cve_service');
    await expect(wrong.connect()).rejects.toThrow(/password authentication failed/);
  });
});

describe.runIf(devPorts)('MinIO bucket policies', () => {
  const s3 = (accessKeyId: string, secretAccessKey: string) =>
    new S3Client({
      endpoint: `http://${host}:9000`,
      region: 'us-east-1',
      forcePathStyle: true,
      credentials: { accessKeyId, secretAccessKey },
    });
  const download = s3('download-service', requireEnv('DOWNLOAD_SERVICE_MINIO_SECRET_KEY'));
  const poc = s3('poc-service', requireEnv('POC_SERVICE_MINIO_SECRET_KEY'));
  const reporting = s3('reporting-service', requireEnv('REPORTING_SERVICE_MINIO_SECRET_KEY'));
  const key = `itest/${Date.now()}.bin`;
  const body = Buffer.from('inert test content');
  const denied = /AccessDenied|Access Denied/;

  it('lets the Download Service manage quarantine and released artifacts only', async () => {
    await download.send(
      new PutObjectCommand({ Bucket: OBJECT_STORAGE_BUCKETS.pocQuarantine, Key: key, Body: body }),
    );
    // Releasing copies the object from quarantine into the released bucket.
    await download.send(
      new CopyObjectCommand({
        Bucket: OBJECT_STORAGE_BUCKETS.pocArtifacts,
        Key: key,
        CopySource: `${OBJECT_STORAGE_BUCKETS.pocQuarantine}/${key}`,
      }),
    );
    await expect(
      download.send(new ListObjectsV2Command({ Bucket: OBJECT_STORAGE_BUCKETS.reports })),
    ).rejects.toThrow(denied);
  });

  it('gives the PoC Service read access to released artifacts only', async () => {
    const object = await poc.send(
      new GetObjectCommand({ Bucket: OBJECT_STORAGE_BUCKETS.pocArtifacts, Key: key }),
    );
    expect(await object.Body?.transformToString()).toBe('inert test content');
    await expect(
      poc.send(new GetObjectCommand({ Bucket: OBJECT_STORAGE_BUCKETS.pocQuarantine, Key: key })),
    ).rejects.toThrow(denied);
    await expect(
      poc.send(
        new PutObjectCommand({ Bucket: OBJECT_STORAGE_BUCKETS.pocArtifacts, Key: `${key}.x`, Body: body }),
      ),
    ).rejects.toThrow(denied);
    await expect(
      poc.send(new DeleteObjectCommand({ Bucket: OBJECT_STORAGE_BUCKETS.pocArtifacts, Key: key })),
    ).rejects.toThrow(denied);
    await download.send(
      new DeleteObjectCommand({ Bucket: OBJECT_STORAGE_BUCKETS.pocArtifacts, Key: key }),
    );
    await download.send(
      new DeleteObjectCommand({ Bucket: OBJECT_STORAGE_BUCKETS.pocQuarantine, Key: key }),
    );
  });

  it('confines the Reporting Service to the reports bucket', async () => {
    await reporting.send(
      new PutObjectCommand({ Bucket: OBJECT_STORAGE_BUCKETS.reports, Key: key, Body: body }),
    );
    await reporting.send(
      new DeleteObjectCommand({ Bucket: OBJECT_STORAGE_BUCKETS.reports, Key: key }),
    );
    await expect(
      reporting.send(
        new GetObjectCommand({ Bucket: OBJECT_STORAGE_BUCKETS.pocQuarantine, Key: key }),
      ),
    ).rejects.toThrow(denied);
  });

  it('denies anonymous access to every bucket', async () => {
    for (const bucket of Object.values(OBJECT_STORAGE_BUCKETS)) {
      const res = await fetch(`http://${host}:9000/${bucket}/`);
      expect(res.status, bucket).toBe(403);
    }
  });
});

describe.runIf(devPorts)('OpenSearch TLS and roles', () => {
  const ca = () => {
    const file = process.env['OPENSEARCH_CA_FILE_FOR_TESTS'] ?? '../../.certs/platform-ca.pem';
    return readFileSync(file, 'utf8');
  };

  function call(method: string, path: string, user: string, password: string, body?: unknown) {
    return new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = request(
        {
          host,
          port: 9200,
          path,
          method,
          ca: ca(),
          servername: 'localhost',
          auth: `${user}:${password}`,
          headers: { 'content-type': 'application/json' },
        },
        (res) => {
          let data = '';
          res.on('data', (chunk: Buffer) => {
            data += chunk.toString();
          });
          res.on('end', () => {
            resolve({ status: res.statusCode ?? 0, body: data });
          });
        },
      );
      req.on('error', reject);
      if (body !== undefined) req.write(JSON.stringify(body));
      req.end();
    });
  }

  const cvePassword = () => requireEnv('CVE_SERVICE_OPENSEARCH_PASSWORD');
  const index = `cve-itest-${Date.now()}`;

  it('serves HTTPS with a certificate signed by the platform CA', async () => {
    const res = await call('GET', '/', 'cve-service', cvePassword());
    expect(res.status).toBe(200);
  });

  it('lets the CVE Service manage cve-* indices only', async () => {
    expect((await call('PUT', `/${index}`, 'cve-service', cvePassword())).status).toBe(200);
    expect(
      (
        await call('PUT', `/${index}/_doc/1`, 'cve-service', cvePassword(), {
          cveId: 'CVE-2026-0001',
        })
      ).status,
    ).toBe(201);
    expect((await call('PUT', '/other-index', 'cve-service', cvePassword())).status).toBe(403);
    expect(
      (await call('GET', '/_plugins/_security/api/internalusers', 'cve-service', cvePassword()))
        .status,
    ).toBe(403);
    expect((await call('DELETE', `/${index}`, 'cve-service', cvePassword())).status).toBe(200);
  });

  it('rejects unknown users and the removed demo accounts', async () => {
    expect((await call('GET', '/', 'cve-service', 'wrong-password-123')).status).toBe(401);
    expect((await call('GET', '/', 'kibanaserver', 'kibanaserver')).status).toBe(401);
    expect((await call('GET', '/', 'admin', 'admin')).status).toBe(401);
  });
});

describe.runIf(devPorts)('RabbitMQ accounts', () => {
  it('has no guest user', async () => {
    const res = await fetch(`http://${host}:15672/api/overview`, {
      headers: { authorization: `Basic ${Buffer.from('guest:guest').toString('base64')}` },
    });
    expect(res.status).toBe(401);
  });
});
