import { createHash, randomUUID } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { Transform, type TransformCallback } from 'node:stream';
import { pipeline } from 'node:stream/promises';

import {
  DOWNLOAD_EVENT_TYPES,
  downloadArtifactScannedPayloadSchema,
  type ArtifactScanner,
  type ArtifactScanStatus,
  type ScanFinding,
  type ScanVerdict,
} from '@cve/contracts';
import type { Logger } from '@cve/logger';

import { aggregateScanStatus } from '../domain/artifact-rules.js';
import {
  deleteReleasedCopies,
  linkedPocArtifacts,
  lockArtifact,
  revokeIfNeeded,
} from '../download/lifecycle.js';
import { downloadEvent, systemContext } from '../events/download-events.js';
import type { PrismaClient } from '../generated/prisma/client.js';
import { toJson, TX_OPTIONS, writeOutbox } from '../persistence/database.js';
import { SCAN_STATUS_TO_API, SCAN_STATUS_TO_DB, VERDICT_TO_DB } from '../persistence/enums.js';
import type { ArtifactObjectStore } from '../storage/object-store.js';
import type { FileScanner, ScannerResult } from './clamav.js';

export interface ScanEngineOptions {
  readonly prisma: PrismaClient;
  readonly store: ArtifactObjectStore;
  /** Configured scanners (a required scanner missing here is reported as not configured). */
  readonly scanners: readonly FileScanner[];
  readonly required: readonly ArtifactScanner[];
  readonly stagingDir: string;
  readonly logger: Logger;
}

export type ScanOutcome =
  | { readonly status: 'skipped'; readonly reason: string }
  | {
      readonly status: 'scanned';
      readonly scanStatus: ArtifactScanStatus;
      /** True when a scanner failed and another attempt could complete the scan. */
      readonly scannerErrors: boolean;
    };

/** Hashes and counts what passes through. */
class Digest extends Transform {
  readonly hash = createHash('sha256');
  bytes = 0;

  constructor(private readonly maxBytes: number) {
    super();
  }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    this.bytes += chunk.length;
    if (this.bytes > this.maxBytes) {
      callback(new Error('the stored object is larger than recorded'));
      return;
    }
    this.hash.update(chunk);
    callback(null, chunk);
  }
}

interface ScannerRun {
  readonly scanner: ArtifactScanner;
  readonly result: ScannerResult;
  readonly startedAt: Date;
  readonly finishedAt: Date;
}

/**
 * Scans a quarantined artifact: streams the object out of quarantine into a private staging
 * file, re-checks its SHA-256 (integrity), runs ClamAV and YARA on the file (both only read it)
 * and records every scanner's result. The aggregated status can only be `clean` when every
 * required scanner ran cleanly. A finding on a released artifact revokes the release.
 */
export class ScanEngine {
  constructor(private readonly options: ScanEngineOptions) {}

  async run(artifactId: string, reason: string, signal: AbortSignal): Promise<ScanOutcome> {
    const { prisma, logger } = this.options;
    const artifact = await prisma.storedArtifact.findUnique({ where: { id: artifactId } });
    if (artifact === null) return { status: 'skipped', reason: 'the artifact does not exist' };
    const previous = SCAN_STATUS_TO_API[artifact.scanStatus];
    await prisma.storedArtifact.update({
      where: { id: artifactId },
      data: { scanStatus: 'scanning' },
    });
    const log = logger.child({ artifactId, reason });
    const scanRunId = randomUUID();
    await mkdir(this.options.stagingDir, { recursive: true, mode: 0o700 });
    const staging = join(this.options.stagingDir, `${randomUUID()}.scan`);
    let runs: ScannerRun[] = [];
    let status: ArtifactScanStatus;
    try {
      const integrity = await this.fetchAndVerify(
        artifact.storageBucket,
        artifact.storageKey,
        Number(artifact.sizeBytes),
        artifact.sha256,
        staging,
        signal,
      );
      if (integrity !== null) {
        log.error({ problem: integrity }, 'stored artifact failed its integrity check');
        status = 'integrity-failure';
      } else {
        runs = await this.scanFile(staging, signal);
        status = aggregateScanStatus(
          runs.map((run) => ({ scanner: run.scanner, verdict: run.result.verdict })),
          this.options.required,
        );
      }
    } catch (error) {
      // Storage or abort failure: restore the previous status; the job (or maintenance) retries.
      await prisma.storedArtifact.update({
        where: { id: artifactId },
        data: { scanStatus: SCAN_STATUS_TO_DB[previous] },
      });
      throw error;
    } finally {
      await rm(staging, { force: true });
    }

    const finalStatus = status;
    const change = await prisma.$transaction(async (tx) => {
      const locked = await lockArtifact(tx, artifactId);
      if (locked === null) return null;
      if (runs.length > 0) {
        await tx.scanResult.createMany({
          data: runs.map((run) => ({
            artifactId,
            scanRunId,
            scanner: run.scanner,
            verdict: VERDICT_TO_DB[run.result.verdict],
            findings: toJson(run.result.findings),
            engineVersion: run.result.engineVersion?.slice(0, 255) ?? null,
            signatureVersion: run.result.signatureVersion?.slice(0, 255) ?? null,
            error: run.result.error?.slice(0, 2_000) ?? null,
            startedAt: run.startedAt,
            finishedAt: run.finishedAt,
          })),
        });
      }
      const updated = await tx.storedArtifact.update({
        where: { id: artifactId },
        data: {
          scanStatus: SCAN_STATUS_TO_DB[finalStatus],
          lastScannedAt: new Date(),
          scanQueuedAt: null,
          version: { increment: 1 },
        },
      });
      const context = systemContext(undefined);
      const revoked = await revokeIfNeeded(tx, updated, `the scan status is ${finalStatus}`, context);
      await writeOutbox(tx, [
        downloadEvent(
          DOWNLOAD_EVENT_TYPES.artifactScanned,
          downloadArtifactScannedPayloadSchema,
          {
            artifactId,
            scanRunId,
            sha256: updated.sha256,
            scanStatus: finalStatus,
            previousScanStatus: previous,
            scanners: runs.map((run) => ({
              scanner: run.scanner,
              verdict: run.result.verdict,
              findings: run.result.findings.map((finding) => finding.name),
            })),
            pocArtifactIds: await linkedPocArtifacts(tx, artifactId),
            lifecycleStatus: revoked.artifact.lifecycleStatus,
          },
          undefined,
        ),
      ]);
      return revoked;
    }, TX_OPTIONS);
    if (change === null) return { status: 'skipped', reason: 'the artifact was removed' };
    await deleteReleasedCopies(this.options.store, prisma, [change.releasedKeyToDelete], log);
    const scannerErrors = runs.some((run) => run.result.verdict === 'error');
    log.info({ scanStatus: finalStatus, scanRunId, scannerErrors }, 'artifact scanned');
    return { status: 'scanned', scanStatus: finalStatus, scannerErrors };
  }

  /** Copies the object into staging while hashing it; returns a problem or null. */
  private async fetchAndVerify(
    bucket: string,
    key: string,
    sizeBytes: number,
    sha256: string,
    staging: string,
    signal: AbortSignal,
  ): Promise<string | null> {
    const digest = new Digest(sizeBytes);
    try {
      const body = await this.options.store.getStream(bucket, key, signal);
      await pipeline(body, digest, createWriteStream(staging, { flags: 'wx', mode: 0o600 }), {
        signal,
      });
    } catch (error) {
      if (signal.aborted) throw error;
      if (error instanceof Error && error.message === 'the stored object is larger than recorded') {
        return error.message;
      }
      throw error;
    }
    if (digest.bytes !== sizeBytes) {
      return `the stored object has ${String(digest.bytes)} bytes, ${String(sizeBytes)} were recorded`;
    }
    const actual = digest.hash.digest('hex');
    return actual === sha256 ? null : `SHA-256 mismatch (stored ${actual})`;
  }

  private async scanFile(path: string, signal: AbortSignal): Promise<ScannerRun[]> {
    const runs: ScannerRun[] = [];
    const names = new Set<ArtifactScanner>([
      ...this.options.required,
      ...this.options.scanners.map((scanner) => scanner.name),
    ]);
    for (const name of names) {
      const startedAt = new Date();
      const scanner = this.options.scanners.find((candidate) => candidate.name === name);
      const result: ScannerResult =
        scanner === undefined
          ? {
              verdict: 'not-configured' satisfies ScanVerdict,
              findings: [] satisfies ScanFinding[],
              engineVersion: null,
              signatureVersion: null,
              error: `${name} is required but not configured`,
            }
          : await scanner.scan(path, signal);
      runs.push({ scanner: name, result, startedAt, finishedAt: new Date() });
    }
    return runs;
  }
}
