import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { ClamdScanner, parseInstreamReply } from '../src/scanning/clamav.js';
import { parseYaraOutput, YaraCliScanner } from '../src/scanning/yara.js';
import { EICAR } from './support.js';

/** A fake clamd that implements zPING, zVERSION and zINSTREAM and flags the EICAR string. */
function fakeClamd(): Promise<{ server: Server; port: number; received: Buffer[] }> {
  const received: Buffer[] = [];
  const server = createServer((socket: Socket) => {
    let buffer = Buffer.alloc(0);
    let streaming = false;
    let content = Buffer.alloc(0);
    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!streaming) {
        const end = buffer.indexOf(0);
        if (end === -1) return;
        const command = buffer.subarray(0, end).toString();
        buffer = buffer.subarray(end + 1);
        if (command === 'zPING') socket.end('PONG\0');
        else if (command === 'zVERSION') socket.end('ClamAV 1.4.0/27000/Wed Nov  5 08:00:00 2026\0');
        else if (command === 'zINSTREAM') streaming = true;
        else socket.end('UNKNOWN COMMAND\0');
      }
      while (streaming && buffer.length >= 4) {
        const length = buffer.readUInt32BE(0);
        if (length === 0) {
          received.push(content);
          socket.end(content.includes(Buffer.from('EICAR')) ? 'stream: Eicar-Test-Signature FOUND\0' : 'stream: OK\0');
          return;
        }
        if (buffer.length < 4 + length) return;
        content = Buffer.concat([content, buffer.subarray(4, 4 + length)]);
        buffer = buffer.subarray(4 + length);
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: (server.address() as AddressInfo).port, received });
    });
  });
}

let clamd: Awaited<ReturnType<typeof fakeClamd>>;
let dir: string;

beforeAll(async () => {
  clamd = await fakeClamd();
  dir = mkdtempSync(join(tmpdir(), 'download-scan-'));
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    clamd.server.close(() => {
      resolve();
    });
  });
  rmSync(dir, { recursive: true, force: true });
});

describe('ClamAV (clamd INSTREAM)', () => {
  it('parses clamd replies', () => {
    expect(parseInstreamReply('stream: OK').verdict).toBe('clean');
    expect(parseInstreamReply('stream: Win.Test.EICAR_HDB-1 FOUND')).toEqual({
      verdict: 'malicious',
      findings: [{ name: 'Win.Test.EICAR_HDB-1', detail: null }],
      error: null,
    });
    expect(parseInstreamReply('INSTREAM size limit exceeded. ERROR').verdict).toBe('error');
  });

  it('streams the file in length-prefixed chunks and reports findings and versions', async () => {
    const scanner = new ClamdScanner({ host: '127.0.0.1', port: clamd.port, timeoutMs: 5_000, chunkBytes: 7 });
    const file = join(dir, 'eicar.txt');
    writeFileSync(file, EICAR);
    const result = await scanner.scan(file, AbortSignal.timeout(5_000));
    expect(result.verdict).toBe('malicious');
    expect(result.findings[0]?.name).toBe('Eicar-Test-Signature');
    expect(result.engineVersion).toBe('ClamAV 1.4.0');
    expect(result.signatureVersion).toContain('27000');
    expect(clamd.received.at(-1)?.toString()).toBe(EICAR);

    const clean = join(dir, 'clean.txt');
    writeFileSync(clean, 'harmless text\n');
    expect((await scanner.scan(clean, AbortSignal.timeout(5_000))).verdict).toBe('clean');
    await scanner.ping();
  });

  it('reports an error (never clean) when clamd is unreachable', async () => {
    const scanner = new ClamdScanner({ host: '127.0.0.1', port: 9, timeoutMs: 1_000 });
    const file = join(dir, 'x.txt');
    writeFileSync(file, 'x');
    const result = await scanner.scan(file, AbortSignal.timeout(5_000));
    expect(result.verdict).toBe('error');
    expect(result.error).not.toBeNull();
  });
});

describe('YARA', () => {
  it('parses matches with namespaces and tags', () => {
    const path = '/tmp/staging/abc.scan';
    expect(
      parseYaraOutput(
        `default:Download_And_Execute_Pipe [dropper] ${path}\ndefault:Plain ${path}\nnoise line\n`,
        path,
      ),
    ).toEqual([
      { name: 'default:Download_And_Execute_Pipe', detail: 'tags: dropper' },
      { name: 'default:Plain', detail: null },
    ]);
  });

  it('reports an error (never clean) when the scanner cannot run', async () => {
    const scanner = new YaraCliScanner({ binary: '/nonexistent/yara', rulesPath: '/nonexistent.yar', timeoutMs: 2_000 });
    const file = join(dir, 'y.txt');
    writeFileSync(file, 'x');
    const result = await scanner.scan(file, AbortSignal.timeout(5_000));
    expect(result.verdict).toBe('error');
    await expect(scanner.ping()).rejects.toThrow();
  });
});
