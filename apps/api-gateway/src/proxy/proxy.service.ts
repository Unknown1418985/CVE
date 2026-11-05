import {
  BadGatewayException,
  BadRequestException,
  GatewayTimeoutException,
  Inject,
  Injectable,
  UnsupportedMediaTypeException,
} from '@nestjs/common';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';

import type { Request, Response } from 'express';

import { getRequestPrincipal } from '@cve/auth';
import {
  CORRELATION_ID_HEADER,
  IDEMPOTENCY_KEY_HEADER,
  type BackendServiceName,
} from '@cve/contracts';
import type { Logger } from '@cve/logger';
import { getCorrelationId } from '@cve/shared';

import type { ServiceRegistry } from '../config/env.js';
import type { HttpFetch } from '../services-health/services-health.constants.js';
import { PROXY_OPTIONS } from './proxy.constants.js';

export interface ProxyOptions {
  readonly registry: ServiceRegistry;
  readonly fetch: HttpFetch;
  readonly timeoutMs: number;
  readonly logger: Logger;
  /** Largest backend response relayed to the client. */
  readonly maxResponseBytes?: number;
  /** Called after a successful logout so the gateway stops accepting the session at once. */
  readonly onSessionEnded?: (sessionId: string) => void;
}

const FORWARDED_REQUEST_HEADERS = [
  'authorization',
  'accept',
  'user-agent',
  'if-match',
  IDEMPOTENCY_KEY_HEADER,
] as const;
const RELAYED_RESPONSE_HEADERS = [
  'content-type',
  'cache-control',
  'www-authenticate',
  'retry-after',
  'location',
  'etag',
  'idempotent-replayed',
] as const;
/** Headers of a streamed download (artifact content), relayed as the backend set them. */
const RELAYED_STREAM_HEADERS = [
  ...RELAYED_RESPONSE_HEADERS,
  'content-length',
  'content-disposition',
  'x-content-type-options',
  'content-security-policy',
  'repr-digest',
  'x-artifact-sha256',
] as const;
const METHODS_WITH_BODY = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
// Dot segments and encoded separators could make the backend resolve a different route than
// the one the gateway authorised, so such paths are refused outright.
const UNSAFE_PATH = /(^|\/)(\.|%2e){1,2}(\/|$)|%2f|%5c|\\|%00/i;

/**
 * Forwards an already authenticated and authorised request to a backend service. The backend
 * validates the same bearer token again (zero trust between services).
 */
@Injectable()
export class ProxyService {
  constructor(@Inject(PROXY_OPTIONS) private readonly options: ProxyOptions) {}

  async forward(service: BackendServiceName, req: Request, res: Response): Promise<void> {
    const upstream = await this.send(service, req);
    const declared = Number(upstream.headers.get('content-length') ?? '0');
    const limit = this.options.maxResponseBytes ?? 10 * 1024 * 1024;
    if (declared > limit) {
      await upstream.body?.cancel();
      throw new BadGatewayException(`${service} response is too large`);
    }
    const payload = Buffer.from(await upstream.arrayBuffer());
    if (payload.length > limit) throw new BadGatewayException(`${service} response is too large`);

    this.afterResponse(req, upstream.status);
    res.status(upstream.status);
    for (const name of RELAYED_RESPONSE_HEADERS) {
      const value = upstream.headers.get(name);
      if (value !== null) res.setHeader(name, value);
    }
    if (payload.length === 0) {
      res.end();
    } else {
      res.end(payload);
    }
  }

  /**
   * Relays a large backend response (artifact content) as a stream, without buffering it or
   * applying the JSON size limit. The backend sets the download headers (attachment disposition,
   * `nosniff`, sandbox CSP, digests), which are relayed unchanged; no other header passes.
   */
  async stream(service: BackendServiceName, req: Request, res: Response): Promise<void> {
    // The timeout covers the response headers; the body then flows as fast as the client reads
    // it and stops when the client disconnects.
    const controller = new AbortController();
    const timer = setTimeout(() => {
      controller.abort(new DOMException('The backend did not respond in time', 'TimeoutError'));
    }, this.options.timeoutMs);
    const onClose = () => {
      controller.abort();
    };
    res.once('close', onClose);
    let upstream: globalThis.Response;
    try {
      upstream = await this.send(service, req, controller.signal);
    } finally {
      clearTimeout(timer);
    }
    res.status(upstream.status);
    for (const name of RELAYED_STREAM_HEADERS) {
      const value = upstream.headers.get(name);
      if (value !== null) res.setHeader(name, value);
    }
    if (upstream.body === null) {
      res.end();
      return;
    }
    const body = Readable.fromWeb(upstream.body as WebReadableStream<Uint8Array>);
    try {
      await pipeline(body, res);
    } catch (error) {
      // Headers are already sent: the client sees a truncated (and digest-mismatching) body.
      this.options.logger.warn(
        { err: error, service, correlationId: getCorrelationId(req) },
        'streamed backend response was interrupted',
      );
      res.destroy();
    } finally {
      res.off('close', onClose);
    }
  }

  /**
   * Sends the request to the backend. `signal` replaces the default timeout, which also covers
   * reading the body (a streamed download sets its own, covering the response headers only).
   */
  private async send(
    service: BackendServiceName,
    req: Request,
    signal: AbortSignal = AbortSignal.timeout(this.options.timeoutMs),
  ): Promise<globalThis.Response> {
    const path = req.originalUrl;
    if (UNSAFE_PATH.test(path.split('?')[0] ?? '')) {
      throw new BadRequestException('Invalid request path');
    }
    const target = `${this.options.registry[service]}${path}`;

    const headers = new Headers();
    for (const name of FORWARDED_REQUEST_HEADERS) {
      const value = req.headers[name];
      if (typeof value === 'string') headers.set(name, value);
    }
    const correlationId = getCorrelationId(req);
    if (correlationId !== undefined) headers.set(CORRELATION_ID_HEADER, correlationId);
    if (req.ip !== undefined) headers.set('x-forwarded-for', req.ip);
    headers.set('x-forwarded-proto', req.protocol);

    let body: string | undefined;
    if (METHODS_WITH_BODY.has(req.method)) {
      const contentType = req.headers['content-type'];
      const hasBody =
        req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0';
      if (hasBody || req.headers['transfer-encoding'] !== undefined) {
        if (contentType === undefined || !/^application\/json(\s*;|$)/i.test(contentType)) {
          throw new UnsupportedMediaTypeException('Request bodies must be application/json');
        }
        body = JSON.stringify(req.body ?? null);
        headers.set('content-type', 'application/json');
      }
    }

    try {
      return await this.options.fetch(target, {
        method: req.method,
        headers,
        ...(body === undefined ? {} : { body }),
        redirect: 'manual',
        signal,
      });
    } catch (error) {
      const timedOut = error instanceof Error && error.name === 'TimeoutError';
      this.options.logger.error(
        { err: error, service, correlationId, method: req.method },
        timedOut ? 'backend request timed out' : 'backend request failed',
      );
      throw timedOut
        ? new GatewayTimeoutException(`${service} did not respond in time`)
        : new BadGatewayException(`${service} is unavailable`);
    }
  }

  private afterResponse(req: Request, status: number): void {
    if (status < 200 || status >= 300 || req.method !== 'POST') return;
    if (req.path !== '/api/v1/auth/logout') return;
    const sessionId = getRequestPrincipal(req)?.sessionId;
    if (sessionId !== undefined) this.options.onSessionEnded?.(sessionId);
  }
}
