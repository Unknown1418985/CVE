import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { AddressPolicy } from '../src/domain/ip-policy.js';
import { DownloadError } from '../src/download/errors.js';
import { SafeFetcher, type FetchPolicy, type Resolver } from '../src/download/safe-fetcher.js';
import { mapResolver, MockSource } from './mock-source.js';
import { createTestCertificate } from './support.js';

// The mock source listens on 127.0.0.1. These tests resolve synthetic `*.test` names to it and
// allow exactly that address as an exception; the SSRF tests use resolvers and policies without
// any exception.

const HOSTS = ['codeload.github.test', 'mirror.github.test', 'evil.test', 'rebind.test'];
const certificate = createTestCertificate(HOSTS);
const source = new MockSource(certificate);
let dir: string;
let counter = 0;

const resolver = mapResolver({
  'codeload.github.test': ['127.0.0.1'],
  'mirror.github.test': ['127.0.0.1'],
  'evil.test': ['127.0.0.1'],
  'rebind.test': ['127.0.0.1', '10.0.0.5'],
  'private.github.test': ['192.168.1.20'],
  'metadata.github.test': ['169.254.169.254'],
});

function fetcher(overrides: { resolver?: Resolver; exceptions?: string[]; totalTimeoutMs?: number; idleTimeoutMs?: number } = {}) {
  return new SafeFetcher({
    addressPolicy: new AddressPolicy(overrides.exceptions ?? ['127.0.0.1/32']),
    userAgent: 'download-service-test',
    resolver: overrides.resolver ?? resolver,
    connectTimeoutMs: 2_000,
    idleTimeoutMs: overrides.idleTimeoutMs ?? 2_000,
    totalTimeoutMs: overrides.totalTimeoutMs ?? 5_000,
    maxRedirects: 3,
    ca: certificate.cert,
  });
}

function policy(overrides: Partial<FetchPolicy> = {}): FetchPolicy {
  return {
    allowedHosts: ['codeload.github.test', 'mirror.github.test', 'rebind.test', 'private.github.test', 'metadata.github.test'],
    allowedPorts: [source.port],
    allowedContentTypes: ['application/x-gzip', 'application/octet-stream'],
    maxBytes: 64 * 1024,
    ...overrides,
  };
}

const destination = () => join(dir, `file-${String((counter += 1))}`);
const url = (host: string, path: string) => `${source.origin(host)}${path}`;

async function failure(promise: Promise<unknown>): Promise<DownloadError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof DownloadError) return error;
    throw error;
  }
  throw new Error('expected the download to fail');
}

const archive = gzipSync(Buffer.from('synthetic test archive '.repeat(100)));

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'download-fetch-'));
  source
    .route('codeload.github.test', '/ok.tar.gz', (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/x-gzip', 'content-length': String(archive.length) });
      res.end(archive);
    })
    .route('codeload.github.test', '/chunked', (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      for (let i = 0; i < 10; i += 1) res.write(archive);
      res.end();
    })
    .route('codeload.github.test', '/redirect-mirror', (_req, res) => {
      res.writeHead(302, { location: `${source.origin('mirror.github.test')}/ok.tar.gz` }).end();
    })
    .route('mirror.github.test', '/ok.tar.gz', (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/x-gzip' }).end(archive);
    })
    .route('codeload.github.test', '/redirect-evil', (_req, res) => {
      res.writeHead(302, { location: `${source.origin('evil.test')}/payload` }).end();
    })
    .route('codeload.github.test', '/redirect-private', (_req, res) => {
      res.writeHead(301, { location: `${source.origin('private.github.test')}/x` }).end();
    })
    .route('codeload.github.test', '/redirect-ip', (_req, res) => {
      res.writeHead(307, { location: `https://127.0.0.1:${String(source.port)}/ok.tar.gz` }).end();
    })
    .route('codeload.github.test', '/redirect-http', (_req, res) => {
      res.writeHead(302, { location: `http://mirror.github.test:${String(source.port)}/ok.tar.gz` }).end();
    })
    .route('codeload.github.test', '/redirect-loop', (_req, res) => {
      res.writeHead(302, { location: '/redirect-loop' }).end();
    })
    .route('codeload.github.test', '/huge-declared', (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/x-gzip', 'content-length': String(10 * 1024 * 1024) });
      res.end();
    })
    .route('codeload.github.test', '/huge-streamed', (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/x-gzip' });
      const chunk = Buffer.alloc(16 * 1024, 1);
      let sent = 0;
      const pump = () => {
        while (sent < 1024 * 1024) {
          sent += chunk.length;
          if (!res.write(chunk)) {
            res.once('drain', pump);
            return;
          }
        }
        res.end();
      };
      pump();
    })
    .route('codeload.github.test', '/html', (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' }).end('<html></html>');
    })
    .route('codeload.github.test', '/encoded', (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/x-gzip', 'content-encoding': 'gzip' }).end(archive);
    })
    .route('codeload.github.test', '/not-found', (_req, res) => {
      res.writeHead(404).end();
    })
    .route('codeload.github.test', '/unavailable', (_req, res) => {
      res.writeHead(503).end();
    })
    .route('codeload.github.test', '/rate-limited', (_req, res) => {
      res.writeHead(429).end();
    })
    .route('codeload.github.test', '/empty', (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/x-gzip' }).end();
    })
    .route('codeload.github.test', '/stall', (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/x-gzip' });
      res.write(archive.subarray(0, 10));
      // Never finishes.
    })
    .route('codeload.github.test', '/truncated', (req, res) => {
      res.writeHead(200, { 'content-type': 'application/x-gzip', 'content-length': '5000' });
      res.write(archive.subarray(0, 100));
      setTimeout(() => req.socket.destroy(), 50);
    });
  await source.start();
});

afterAll(async () => {
  await source.stop();
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  source.requests.length = 0;
});

describe('SafeFetcher', () => {
  it('streams a file to disk with its SHA-256, size, head and provenance', async () => {
    const target = destination();
    const result = await fetcher().fetchToFile(url('codeload.github.test', '/ok.tar.gz'), policy(), target, AbortSignal.timeout(5_000));
    expect(result.sha256).toBe(createHash('sha256').update(archive).digest('hex'));
    expect(result.bytes).toBe(archive.length);
    expect(readFileSync(target).equals(archive)).toBe(true);
    expect(result.head.subarray(0, 2)).toEqual(Buffer.from([0x1f, 0x8b]));
    expect(result.hops).toEqual([
      expect.objectContaining({ resolvedAddresses: ['127.0.0.1'], connectedAddress: '127.0.0.1', status: 200 }),
    ]);
    expect(source.requests[0]?.headers['accept-encoding']).toBe('identity');
  });

  it('streams chunked responses without a declared length', async () => {
    const result = await fetcher().fetchToFile(url('codeload.github.test', '/chunked'), policy(), destination(), AbortSignal.timeout(5_000));
    expect(result.bytes).toBe(archive.length * 10);
    expect(result.declaredLength).toBeNull();
  });

  it('follows a redirect to another allowlisted host and records every hop', async () => {
    const result = await fetcher().fetchToFile(url('codeload.github.test', '/redirect-mirror'), policy(), destination(), AbortSignal.timeout(5_000));
    expect(result.finalUrl).toBe(url('mirror.github.test', '/ok.tar.gz'));
    expect(result.hops.map((hop) => hop.status)).toEqual([302, 200]);
  });

  it('refuses a redirect to a host outside the allowlist without contacting it', async () => {
    const error = await failure(
      fetcher().fetchToFile(url('codeload.github.test', '/redirect-evil'), policy(), destination(), AbortSignal.timeout(5_000)),
    );
    expect(error.code).toBe('host-not-allowed');
    expect(error.retryable).toBe(false);
    expect(source.requests.map((request) => request.host)).not.toContain('evil.test');
  });

  it('revalidates DNS after a redirect and blocks private destinations', async () => {
    const error = await failure(
      fetcher().fetchToFile(url('codeload.github.test', '/redirect-private'), policy(), destination(), AbortSignal.timeout(5_000)),
    );
    expect(error.code).toBe('address-blocked');
    expect(error.hops).toHaveLength(2);
    expect(error.hops[1]?.resolvedAddresses).toEqual(['192.168.1.20']);
  });

  it('refuses redirects to IP literals and to plain http', async () => {
    expect(
      (await failure(fetcher().fetchToFile(url('codeload.github.test', '/redirect-ip'), policy(), destination(), AbortSignal.timeout(5_000)))).code,
    ).toBe('host-not-allowed');
    expect(
      (await failure(fetcher().fetchToFile(url('codeload.github.test', '/redirect-http'), policy(), destination(), AbortSignal.timeout(5_000)))).code,
    ).toBe('invalid-redirect');
  });

  it('stops redirect loops', async () => {
    const error = await failure(
      fetcher().fetchToFile(url('codeload.github.test', '/redirect-loop'), policy(), destination(), AbortSignal.timeout(5_000)),
    );
    expect(error.code).toBe('too-many-redirects');
  });

  it('blocks loopback, link-local (metadata) and private answers when no exception applies', async () => {
    const strict = fetcher({ exceptions: [] });
    expect((await failure(strict.fetchToFile(url('codeload.github.test', '/ok.tar.gz'), policy(), destination(), AbortSignal.timeout(5_000)))).code).toBe(
      'address-blocked',
    );
    expect((await failure(strict.fetchToFile(url('metadata.github.test', '/latest'), policy(), destination(), AbortSignal.timeout(5_000)))).code).toBe(
      'address-blocked',
    );
    expect(source.requests).toHaveLength(0);
  });

  it('refuses a name whose answers mix public and private addresses (rebinding)', async () => {
    const error = await failure(
      fetcher().fetchToFile(url('rebind.test', '/ok.tar.gz'), policy(), destination(), AbortSignal.timeout(5_000)),
    );
    expect(error.code).toBe('address-blocked');
  });

  it('refuses URLs outside the policy before any network access', async () => {
    const f = fetcher();
    const cases: [string, string][] = [
      [`http://codeload.github.test:${String(source.port)}/ok.tar.gz`, 'url-not-allowed'],
      [url('evil.test', '/payload'), 'host-not-allowed'],
      [`https://u:p@codeload.github.test:${String(source.port)}/ok.tar.gz`, 'url-not-allowed'],
      ['https://codeload.github.test:8443/ok.tar.gz', 'url-not-allowed'],
      [`https://[::1]:${String(source.port)}/`, 'host-not-allowed'],
    ];
    for (const [target, code] of cases) {
      expect((await failure(f.fetchToFile(target, policy(), destination(), AbortSignal.timeout(5_000)))).code).toBe(code);
    }
    expect(source.requests).toHaveLength(0);
  });

  it('enforces the declared and the streamed size limit', async () => {
    const declared = await failure(
      fetcher().fetchToFile(url('codeload.github.test', '/huge-declared'), policy(), destination(), AbortSignal.timeout(5_000)),
    );
    expect(declared.code).toBe('size-limit-exceeded');
    const streamed = await failure(
      fetcher().fetchToFile(url('codeload.github.test', '/huge-streamed'), policy(), destination(), AbortSignal.timeout(5_000)),
    );
    expect(streamed.code).toBe('size-limit-exceeded');
    expect(streamed.bytesReceived).toBeLessThanOrEqual(64 * 1024 + 16 * 1024);
  });

  it('refuses content types and encodings the source does not allow', async () => {
    expect((await failure(fetcher().fetchToFile(url('codeload.github.test', '/html'), policy(), destination(), AbortSignal.timeout(5_000)))).code).toBe(
      'content-type-not-allowed',
    );
    expect((await failure(fetcher().fetchToFile(url('codeload.github.test', '/encoded'), policy(), destination(), AbortSignal.timeout(5_000)))).code).toBe(
      'unsupported-encoding',
    );
  });

  it('classifies HTTP failures as retryable or not', async () => {
    const notFound = await failure(fetcher().fetchToFile(url('codeload.github.test', '/not-found'), policy(), destination(), AbortSignal.timeout(5_000)));
    expect([notFound.code, notFound.retryable, notFound.httpStatus]).toEqual(['http-error', false, 404]);
    const unavailable = await failure(fetcher().fetchToFile(url('codeload.github.test', '/unavailable'), policy(), destination(), AbortSignal.timeout(5_000)));
    expect([unavailable.code, unavailable.retryable]).toEqual(['http-error', true]);
    const limited = await failure(fetcher().fetchToFile(url('codeload.github.test', '/rate-limited'), policy(), destination(), AbortSignal.timeout(5_000)));
    expect([limited.code, limited.retryable]).toEqual(['rate-limited', true]);
    const empty = await failure(fetcher().fetchToFile(url('codeload.github.test', '/empty'), policy(), destination(), AbortSignal.timeout(5_000)));
    expect(empty.code).toBe('empty-response');
  });

  it('times out a stalled transfer and detects truncation', async () => {
    const stalled = await failure(
      fetcher({ idleTimeoutMs: 1_000, totalTimeoutMs: 3_000 }).fetchToFile(url('codeload.github.test', '/stall'), policy(), destination(), AbortSignal.timeout(10_000)),
    );
    expect(stalled.code).toBe('timeout');
    expect(stalled.retryable).toBe(true);
    const truncated = await failure(
      fetcher().fetchToFile(url('codeload.github.test', '/truncated'), policy(), destination(), AbortSignal.timeout(5_000)),
    );
    expect(truncated.retryable).toBe(true);
  });

  it('fails TLS verification for an untrusted certificate', async () => {
    const untrusted = new SafeFetcher({
      addressPolicy: new AddressPolicy(['127.0.0.1/32']),
      userAgent: 'download-service-test',
      resolver,
      connectTimeoutMs: 2_000,
      idleTimeoutMs: 2_000,
      totalTimeoutMs: 5_000,
      maxRedirects: 3,
    });
    const error = await failure(untrusted.fetchToFile(url('codeload.github.test', '/ok.tar.gz'), policy(), destination(), AbortSignal.timeout(5_000)));
    expect(error.code).toBe('tls-failure');
  });
});
