import { createServer, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

import type { Resolver } from '../src/download/safe-fetcher.js';
import type { TestCertificate } from './support.js';

export type MockHandler = (req: IncomingMessage, res: ServerResponse) => void;

/**
 * A local HTTPS server standing in for public sources. Tests resolve the synthetic host names
 * (`*.test`) to 127.0.0.1 through an injected resolver and allow 127.0.0.1 as an exception.
 */
export class MockSource {
  private readonly routes = new Map<string, MockHandler>();
  readonly requests: { host: string; path: string; headers: IncomingMessage['headers'] }[] = [];
  private server: Server | undefined;
  port = 0;

  constructor(private readonly certificate: TestCertificate) {}

  route(host: string, path: string, handler: MockHandler): this {
    this.routes.set(`${host}${path}`, handler);
    return this;
  }

  async start(): Promise<void> {
    this.server = createServer(
      { key: this.certificate.key, cert: this.certificate.cert },
      (req, res) => {
        const host = (req.headers.host ?? '').split(':')[0] ?? '';
        const path = req.url ?? '/';
        this.requests.push({ host, path, headers: req.headers });
        const handler = this.routes.get(`${host}${path}`);
        if (handler === undefined) {
          res.writeHead(404).end('not found');
          return;
        }
        handler(req, res);
      },
    );
    await new Promise<void>((resolve) => this.server?.listen(0, '127.0.0.1', resolve));
    this.port = (this.server.address() as AddressInfo).port;
  }

  origin(host: string): string {
    return `https://${host}:${String(this.port)}`;
  }

  async stop(): Promise<void> {
    this.server?.closeAllConnections();
    const server = this.server;
    if (server === undefined) return;
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
  }
}

/** Resolves the given names; anything else fails like NXDOMAIN. */
export function mapResolver(entries: Record<string, readonly string[]>): Resolver {
  return (hostname) => {
    const addresses = entries[hostname];
    if (addresses === undefined) return Promise.reject(new Error(`ENOTFOUND ${hostname}`));
    return Promise.resolve(
      addresses.map((address) => ({
        address,
        family: address.includes(':') ? (6 as const) : (4 as const),
      })),
    );
  };
}

/** A minimal gzip member (magic bytes + payload) for content-type checks. */
export function gzipLike(payload: string): Buffer {
  return Buffer.concat([Buffer.from([0x1f, 0x8b, 0x08, 0x00]), Buffer.from(payload)]);
}
