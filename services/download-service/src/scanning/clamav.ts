import { createReadStream } from 'node:fs';
import { connect, type Socket } from 'node:net';

import type { ScanFinding, ScanVerdict } from '@cve/contracts';

export interface ScannerResult {
  readonly verdict: ScanVerdict;
  readonly findings: ScanFinding[];
  readonly engineVersion: string | null;
  readonly signatureVersion: string | null;
  readonly error: string | null;
}

/** Scans a local file. Implementations read the file as data; they never execute it. */
export interface FileScanner {
  readonly name: 'clamav' | 'yara';
  scan(path: string, signal: AbortSignal): Promise<ScannerResult>;
  ping(): Promise<void>;
}

export interface ClamdOptions {
  readonly host: string;
  readonly port: number;
  readonly timeoutMs: number;
  /** Bytes per INSTREAM chunk (clamd's default StreamMaxLength is 25 MiB in total). */
  readonly chunkBytes?: number;
}

const MAX_REPLY_BYTES = 64 * 1024;

/**
 * ClamAV client speaking clamd's TCP protocol (`zINSTREAM`): the file is streamed to the
 * daemon in length-prefixed chunks, so clamd never needs access to this container's files.
 */
export class ClamdScanner implements FileScanner {
  readonly name = 'clamav' as const;

  constructor(private readonly options: ClamdOptions) {}

  private exchange(
    signal: AbortSignal | undefined,
    send: (socket: Socket) => Promise<void>,
  ): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const socket = connect({ host: this.options.host, port: this.options.port });
      const chunks: Buffer[] = [];
      let size = 0;
      let settled = false;
      const finish = (error: Error | null, reply?: string) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        socket.destroy();
        if (error === null) resolve(reply ?? '');
        else reject(error);
      };
      const timer = setTimeout(() => {
        finish(new Error(`clamd did not answer within ${String(this.options.timeoutMs)} ms`));
      }, this.options.timeoutMs);
      const onAbort = () => {
        finish(new Error('scan aborted'));
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      socket.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_REPLY_BYTES) {
          finish(new Error('clamd reply is too long'));
          return;
        }
        chunks.push(chunk);
        // Replies to z-commands end with a NUL byte.
        if (chunk.includes(0)) finish(null, Buffer.concat(chunks).toString('utf8').replace(/\0.*$/s, ''));
      });
      socket.on('error', (error) => {
        finish(error);
      });
      socket.on('end', () => {
        finish(null, Buffer.concat(chunks).toString('utf8').replace(/\0.*$/s, ''));
      });
      socket.once('connect', () => {
        send(socket).catch((error: unknown) => {
          finish(error instanceof Error ? error : new Error(String(error)));
        });
      });
    });
  }

  private async command(command: string): Promise<string> {
    return (
      await this.exchange(undefined, async (socket) => {
        socket.write(`z${command}\0`);
        await Promise.resolve();
      })
    ).trim();
  }

  async ping(): Promise<void> {
    const reply = await this.command('PING');
    if (reply !== 'PONG') throw new Error(`unexpected clamd reply: ${reply.slice(0, 100)}`);
  }

  /** `ClamAV 1.4.1/27450/Tue Nov  4 08:00:00 2026` → engine and signature versions. */
  async version(): Promise<{ engine: string | null; signatures: string | null }> {
    const reply = await this.command('VERSION');
    const [engine, signatures, date] = reply.split('/');
    return {
      engine: engine?.trim() ?? null,
      signatures:
        signatures === undefined ? null : [signatures.trim(), date?.trim()].filter(Boolean).join(' '),
    };
  }

  async scan(path: string, signal: AbortSignal): Promise<ScannerResult> {
    const chunkBytes = this.options.chunkBytes ?? 64 * 1024;
    let version: { engine: string | null; signatures: string | null } = {
      engine: null,
      signatures: null,
    };
    try {
      version = await this.version();
      const reply = (
        await this.exchange(signal, async (socket) => {
          socket.write('zINSTREAM\0');
          for await (const chunk of createReadStream(path, { highWaterMark: chunkBytes })) {
            const data = chunk as Buffer;
            const length = Buffer.alloc(4);
            length.writeUInt32BE(data.length);
            if (!socket.write(Buffer.concat([length, data]))) {
              await new Promise<void>((resolve) => socket.once('drain', resolve));
            }
          }
          socket.write(Buffer.alloc(4));
        })
      ).trim();
      return { ...parseInstreamReply(reply), engineVersion: version.engine, signatureVersion: version.signatures };
    } catch (error) {
      return {
        verdict: 'error',
        findings: [],
        engineVersion: version.engine,
        signatureVersion: version.signatures,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

/** `stream: OK`, `stream: Eicar-Signature FOUND` or `… ERROR`. */
export function parseInstreamReply(
  reply: string,
): Pick<ScannerResult, 'verdict' | 'findings' | 'error'> {
  const body = reply.replace(/^stream:\s*/, '');
  if (body === 'OK') return { verdict: 'clean', findings: [], error: null };
  const found = /^(.+) FOUND$/.exec(body);
  if (found?.[1] !== undefined) {
    return { verdict: 'malicious', findings: [{ name: found[1].trim().slice(0, 255), detail: null }], error: null };
  }
  return { verdict: 'error', findings: [], error: `clamd: ${body.slice(0, 500) || 'empty reply'}` };
}
