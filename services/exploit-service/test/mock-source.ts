import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface MockResponse {
  readonly status?: number;
  readonly headers?: Record<string, string>;
  /** Serialised as JSON unless it is a string. */
  readonly body?: unknown;
  /** Wait before answering (timeouts). */
  readonly delayMs?: number;
}

export interface RecordedRequest {
  readonly path: string;
  readonly query: URLSearchParams;
  readonly headers: IncomingHttpHeaders;
}

export type MockHandler = (request: RecordedRequest) => MockResponse | Promise<MockResponse>;

/**
 * Local HTTP server that stands in for an external API. Routes are matched by path; every
 * request is recorded so tests can assert pagination parameters and headers.
 */
export class MockSource {
  readonly requests: RecordedRequest[] = [];
  private readonly routes = new Map<string, MockHandler>();
  private server: Server | undefined;
  origin = '';

  route(path: string, handler: MockHandler): this {
    this.routes.set(path, handler);
    return this;
  }

  /** Answers the queued responses in order, then repeats the last one. */
  sequence(path: string, responses: readonly MockResponse[]): this {
    let index = 0;
    return this.route(path, () => {
      const response = responses[Math.min(index, responses.length - 1)] ?? { status: 500 };
      index += 1;
      return response;
    });
  }

  requestsTo(path: string): RecordedRequest[] {
    return this.requests.filter((request) => request.path === path);
  }

  async start(): Promise<this> {
    this.server = createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      const recorded = { path: url.pathname, query: url.searchParams, headers: req.headers };
      this.requests.push(recorded);
      const handler = this.routes.get(url.pathname);
      void Promise.resolve(
        handler === undefined ? { status: 404, body: { message: 'not found' } } : handler(recorded),
      )
        .then(async (response) => {
          if (response.delayMs !== undefined)
            await new Promise((r) => setTimeout(r, response.delayMs));
          const body =
            response.body === undefined
              ? ''
              : typeof response.body === 'string'
                ? response.body
                : JSON.stringify(response.body);
          res.writeHead(response.status ?? 200, {
            'content-type': 'application/json; charset=utf-8',
            ...response.headers,
          });
          res.end(body);
        })
        .catch(() => {
          res.writeHead(500);
          res.end();
        });
    });
    await new Promise<void>((resolve) => this.server?.listen(0, '127.0.0.1', resolve));
    const address = this.server.address() as AddressInfo;
    this.origin = `http://127.0.0.1:${address.port}`;
    return this;
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
