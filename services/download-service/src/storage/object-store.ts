import { createReadStream } from 'node:fs';
import type { Readable } from 'node:stream';

import {
  CopyObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
  HeadObjectCommand,
  NoSuchKey,
  NotFound,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';

import type { ObjectStorageEnv } from '@cve/config';

export interface StoredObjectInfo {
  readonly sizeBytes: number;
  readonly sha256: string | null;
}

/**
 * Object storage used by the Download Service. Objects are always written as
 * `application/octet-stream` with `Content-Disposition: attachment`, so nothing stored is ever
 * rendered by a browser even if it were served directly.
 */
export interface ArtifactObjectStore {
  /** Uploads a local file; the store verifies the SHA-256 it is given. */
  putFile(input: {
    bucket: string;
    key: string;
    path: string;
    sizeBytes: number;
    sha256: string;
    metadata: Record<string, string>;
  }): Promise<void>;
  getStream(bucket: string, key: string, signal?: AbortSignal): Promise<Readable>;
  head(bucket: string, key: string): Promise<StoredObjectInfo | null>;
  copy(input: { fromBucket: string; fromKey: string; toBucket: string; toKey: string }): Promise<void>;
  delete(bucket: string, key: string): Promise<void>;
  ping(bucket: string): Promise<void>;
}

const hexToBase64 = (hex: string) => Buffer.from(hex, 'hex').toString('base64');
const base64ToHex = (value: string) => Buffer.from(value, 'base64').toString('hex');

/** S3 (MinIO) implementation with the service's least-privilege credentials. */
export class S3ArtifactObjectStore implements ArtifactObjectStore {
  readonly client: S3Client;

  constructor(env: ObjectStorageEnv, requestTimeoutMs = 60_000) {
    this.client = new S3Client({
      endpoint: env.S3_ENDPOINT,
      region: env.S3_REGION,
      forcePathStyle: env.S3_FORCE_PATH_STYLE,
      credentials: { accessKeyId: env.S3_ACCESS_KEY_ID, secretAccessKey: env.S3_SECRET_ACCESS_KEY },
      requestChecksumCalculation: 'WHEN_REQUIRED',
      responseChecksumValidation: 'WHEN_REQUIRED',
      requestHandler: { requestTimeout: requestTimeoutMs, connectionTimeout: 5_000 },
    });
  }

  async putFile(input: {
    bucket: string;
    key: string;
    path: string;
    sizeBytes: number;
    sha256: string;
    metadata: Record<string, string>;
  }): Promise<void> {
    await this.client.send(
      new PutObjectCommand({
        Bucket: input.bucket,
        Key: input.key,
        Body: createReadStream(input.path),
        ContentLength: input.sizeBytes,
        ContentType: 'application/octet-stream',
        ContentDisposition: 'attachment',
        // The server recomputes the digest and refuses the upload when it differs.
        ChecksumSHA256: hexToBase64(input.sha256),
        Metadata: { ...input.metadata, sha256: input.sha256 },
      }),
    );
  }

  async getStream(bucket: string, key: string, signal?: AbortSignal): Promise<Readable> {
    const response = await this.client.send(
      new GetObjectCommand({ Bucket: bucket, Key: key }),
      signal === undefined ? {} : { abortSignal: signal },
    );
    const body = response.Body as Readable | undefined;
    if (body === undefined) throw new Error(`Object ${bucket}/${key} has no body`);
    return body;
  }

  async head(bucket: string, key: string): Promise<StoredObjectInfo | null> {
    try {
      const response = await this.client.send(
        new HeadObjectCommand({ Bucket: bucket, Key: key, ChecksumMode: 'ENABLED' }),
      );
      const metadataSha = response.Metadata?.['sha256'];
      return {
        sizeBytes: response.ContentLength ?? 0,
        sha256:
          response.ChecksumSHA256 === undefined
            ? (metadataSha ?? null)
            : base64ToHex(response.ChecksumSHA256),
      };
    } catch (error) {
      if (error instanceof NotFound || error instanceof NoSuchKey) return null;
      throw error;
    }
  }

  async copy(input: {
    fromBucket: string;
    fromKey: string;
    toBucket: string;
    toKey: string;
  }): Promise<void> {
    await this.client.send(
      new CopyObjectCommand({
        Bucket: input.toBucket,
        Key: input.toKey,
        CopySource: `${input.fromBucket}/${input.fromKey}`,
        MetadataDirective: 'COPY',
      }),
    );
  }

  async delete(bucket: string, key: string): Promise<void> {
    await this.client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
  }

  async ping(bucket: string): Promise<void> {
    await this.client.send(new HeadBucketCommand({ Bucket: bucket }));
  }

  close(): void {
    this.client.destroy();
  }
}
