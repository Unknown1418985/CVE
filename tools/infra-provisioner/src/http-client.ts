import { request as httpRequest, type IncomingHttpHeaders } from 'node:http';
import { request as httpsRequest } from 'node:https';

export interface HttpResponse {
  readonly status: number;
  readonly headers: IncomingHttpHeaders;
  readonly body: unknown;
}

export interface HttpClientOptions {
  readonly baseUrl: string;
  readonly username: string;
  readonly password: string;
  readonly timeoutMs: number;
  /** PEM CA bundle used to verify HTTPS servers. Certificate verification is never disabled. */
  readonly ca?: string;
}

export class HttpError extends Error {
  constructor(
    readonly method: string,
    readonly path: string,
    readonly status: number,
    readonly body: unknown,
  ) {
    super(`${method} ${path} failed with HTTP ${status}: ${JSON.stringify(body).slice(0, 300)}`);
    this.name = 'HttpError';
  }
}

/** Minimal JSON client over node:http(s) with basic auth, timeouts and custom CA support. */
export class HttpClient {
  private readonly base: URL;

  constructor(private readonly options: HttpClientOptions) {
    this.base = new URL(options.baseUrl);
  }

  request(method: string, path: string, body?: unknown): Promise<HttpResponse> {
    const url = new URL(path, this.base);
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), 'utf8');
    const send = url.protocol === 'https:' ? httpsRequest : httpRequest;
    const auth = Buffer.from(`${this.options.username}:${this.options.password}`).toString(
      'base64',
    );

    return new Promise<HttpResponse>((resolve, reject) => {
      const req = send(
        url,
        {
          method,
          timeout: this.options.timeoutMs,
          headers: {
            authorization: `Basic ${auth}`,
            // Some RabbitMQ endpoints (user limits) answer 406 to a strict JSON-only Accept header.
            accept: 'application/json, */*;q=0.1',
            ...(payload
              ? { 'content-type': 'application/json', 'content-length': payload.length }
              : {}),
          },
          ...(this.options.ca === undefined ? {} : { ca: this.options.ca }),
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let parsed: unknown = text;
            if (text.length > 0) {
              try {
                parsed = JSON.parse(text);
              } catch {
                parsed = text;
              }
            }
            resolve({ status: res.statusCode ?? 0, headers: res.headers, body: parsed });
          });
          res.on('error', reject);
        },
      );
      req.on('timeout', () => {
        req.destroy(
          new Error(`${method} ${url.pathname} timed out after ${this.options.timeoutMs}ms`),
        );
      });
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  /** Performs the request and throws {@link HttpError} unless the status is 2xx (or allowed). */
  async expect(
    method: string,
    path: string,
    body?: unknown,
    allowed: readonly number[] = [],
  ): Promise<HttpResponse> {
    const response = await this.request(method, path, body);
    if ((response.status >= 200 && response.status < 300) || allowed.includes(response.status)) {
      return response;
    }
    throw new HttpError(method, path, response.status, response.body);
  }
}

/** Retries `check` until it resolves or the deadline passes, with capped exponential backoff. */
export async function waitUntil(
  description: string,
  check: () => Promise<void>,
  options: { timeoutMs: number; onRetry?: (error: unknown, delayMs: number) => void },
): Promise<void> {
  const deadline = Date.now() + options.timeoutMs;
  let delayMs = 500;
  for (;;) {
    try {
      await check();
      return;
    } catch (error) {
      if (Date.now() + delayMs > deadline) {
        throw new Error(`Timed out waiting for ${description}`, { cause: error });
      }
      options.onRetry?.(error, delayMs);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      delayMs = Math.min(delayMs * 2, 5_000);
    }
  }
}
