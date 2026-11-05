import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';

import type { INestApplication } from '@nestjs/common';

import { createTokenVerifier } from '@cve/auth';
import { createLogger, type Logger } from '@cve/logger';
import { configureServiceApp, type HealthIndicator } from '@cve/shared';
import { buildServiceTestEnv, createHttpTestApp, type HttpTestApp } from '@cve/testing';
import type { TestTokenIssuer } from '@cve/testing/auth';

import { AppModule } from '../src/app.module.js';
import { loadServiceEnv, type Env } from '../src/config/env.js';
import type { DownloadJobQueue } from '../src/download/download-jobs.js';
import { buildSourcePolicies } from '../src/download/source-catalog.js';
import { createPrismaClient, type PrismaClient } from '../src/persistence/prisma.js';
import { SERVICE_NAME } from '../src/service.js';
import type { ArtifactObjectStore, StoredObjectInfo } from '../src/storage/object-store.js';

export const silentLogger: Logger = createLogger({ service: SERVICE_NAME, level: 'silent' });

export function downloadTestEnv(overrides: Record<string, string> = {}): Env {
  return loadServiceEnv(
    buildServiceTestEnv(SERVICE_NAME, {
      KEYCLOAK_URL: 'http://keycloak.test/auth',
      KEYCLOAK_PUBLIC_URL: 'http://keycloak.test/auth',
      OUTBOX_RELAY_ENABLED: 'false',
      EVENT_CONSUMERS_ENABLED: 'false',
      DOWNLOAD_WORKER_ENABLED: 'false',
      ...overrides,
    }),
  );
}

/** A Prisma client for a server that does not exist (HTTP tests stop before the database). */
export function unreachablePrisma(): PrismaClient {
  return createPrismaClient('postgresql://download_service:unused@127.0.0.1:9/download_service');
}

/** Records queued work instead of sending it to Redis. */
export class FakeJobQueue implements DownloadJobQueue {
  readonly requests: string[] = [];
  readonly scans: { artifactId: string; reason: string }[] = [];

  queueRequest(requestId: string): Promise<boolean> {
    this.requests.push(requestId);
    return Promise.resolve(true);
  }

  enqueueScan(artifactId: string, reason: string): Promise<boolean> {
    this.scans.push({ artifactId, reason });
    return Promise.resolve(true);
  }
}

/** In-memory object store with the same contract as MinIO (checksum verified on upload). */
export class MemoryObjectStore implements ArtifactObjectStore {
  readonly objects = new Map<string, Buffer>();

  putFile(input: { bucket: string; key: string; path: string; sha256: string }): Promise<void> {
    this.objects.set(`${input.bucket}/${input.key}`, readFileSync(input.path));
    return Promise.resolve();
  }

  getStream(bucket: string, key: string): Promise<Readable> {
    const body = this.objects.get(`${bucket}/${key}`);
    if (body === undefined) return Promise.reject(new Error('NoSuchKey'));
    return Promise.resolve(Readable.from([body]));
  }

  head(bucket: string, key: string): Promise<StoredObjectInfo | null> {
    const body = this.objects.get(`${bucket}/${key}`);
    return Promise.resolve(body === undefined ? null : { sizeBytes: body.length, sha256: null });
  }

  copy(input: {
    fromBucket: string;
    fromKey: string;
    toBucket: string;
    toKey: string;
  }): Promise<void> {
    const body = this.objects.get(`${input.fromBucket}/${input.fromKey}`);
    if (body === undefined) return Promise.reject(new Error('NoSuchKey'));
    this.objects.set(`${input.toBucket}/${input.toKey}`, body);
    return Promise.resolve();
  }

  delete(bucket: string, key: string): Promise<void> {
    this.objects.delete(`${bucket}/${key}`);
    return Promise.resolve();
  }

  ping(): Promise<void> {
    return Promise.resolve();
  }
}

export async function startDownloadApp(
  issuer: TestTokenIssuer,
  options: {
    prisma?: PrismaClient;
    jobs?: DownloadJobQueue | null;
    store?: ArtifactObjectStore;
    env?: Env;
    healthIndicators?: readonly HealthIndicator[];
  } = {},
): Promise<HttpTestApp> {
  const env = options.env ?? downloadTestEnv();
  return createHttpTestApp(
    AppModule.register(env, {
      logger: silentLogger,
      verifier: createTokenVerifier({
        issuer: issuer.issuer,
        audience: issuer.audience,
        keys: issuer.getKey,
      }),
      prisma: options.prisma ?? unreachablePrisma(),
      healthIndicators: options.healthIndicators ?? [],
      jobs: options.jobs === undefined ? new FakeJobQueue() : options.jobs,
      store: options.store ?? new MemoryObjectStore(),
      sources: buildSourcePolicies(env),
      settings: { maxAttempts: env.DOWNLOAD_JOB_ATTEMPTS },
    }),
    (app: INestApplication) => {
      configureServiceApp(app, {
        service: SERVICE_NAME,
        version: '0.0.0-test',
        logger: silentLogger,
        corsAllowedOrigins: [],
        swaggerEnabled: false,
      });
    },
  );
}

export interface TestCertificate {
  readonly key: string;
  readonly cert: string;
}

/**
 * A throw-away self-signed certificate for the mock sources (generated with `openssl`, never
 * committed). The fetcher trusts it only because tests pass it as an extra CA.
 */
export function createTestCertificate(hosts: readonly string[]): TestCertificate {
  const dir = mkdtempSync(join(tmpdir(), 'download-tls-'));
  try {
    const key = join(dir, 'key.pem');
    const cert = join(dir, 'cert.pem');
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=download-service-test',
        '-addext',
        `subjectAltName=${hosts.map((host) => `DNS:${host}`).join(',')}`,
        '-keyout',
        key,
        '-out',
        cert,
      ],
      { stdio: 'pipe' },
    );
    return { key: readFileSync(key, 'utf8'), cert: readFileSync(cert, 'utf8') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Synthetic test content (never real malware): the EICAR antivirus test string. */
export const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
