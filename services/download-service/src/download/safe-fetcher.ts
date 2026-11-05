import { createHash } from 'node:crypto';
import { lookup as dnsLookup } from 'node:dns/promises';
import { createWriteStream } from 'node:fs';
import type { IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP, type LookupFunction } from 'node:net';
import { Transform, type TransformCallback } from 'node:stream';
import { pipeline } from 'node:stream/promises';

import type { DownloadHop } from '@cve/contracts';

import { essence, SNIFF_BYTES } from '../domain/file-type.js';
import type { AddressPolicy } from '../domain/ip-policy.js';
import { DownloadError } from './errors.js';

export interface ResolvedAddress {
  readonly address: string;
  readonly family: 4 | 6;
}

/** DNS resolution; replaced in tests so a mock source can stand in for a public host. */
export type Resolver = (hostname: string) => Promise<readonly ResolvedAddress[]>;

export const systemResolver: Resolver = async (hostname) => {
  const answers = await dnsLookup(hostname, { all: true, verbatim: true });
  return answers.map((answer) => ({
    address: answer.address,
    family: answer.family === 6 ? 6 : 4,
  }));
};

/** What one source allows; every hop of a request is checked against it. */
export interface FetchPolicy {
  /** Lower-case host names (exact match). */
  readonly allowedHosts: readonly string[];
  /** Ports allowed in URLs; `443` for https URLs without a port. */
  readonly allowedPorts: readonly number[];
  readonly allowedContentTypes: readonly string[];
  readonly maxBytes: number;
}

export interface SafeFetcherOptions {
  readonly addressPolicy: AddressPolicy;
  readonly userAgent: string;
  readonly resolver?: Resolver;
  /** Time until the response headers arrive (TCP, TLS and the server's first answer). */
  readonly connectTimeoutMs: number;
  /** Longest pause without data once connected. */
  readonly idleTimeoutMs: number;
  /** Deadline for the whole download including redirects. */
  readonly totalTimeoutMs: number;
  readonly maxRedirects: number;
  /** Extra trusted CA certificates (tests); the system store is used otherwise. */
  readonly ca?: string | Buffer;
}

export interface FetchResult {
  readonly hops: DownloadHop[];
  readonly finalUrl: string;
  readonly httpStatus: number;
  readonly declaredContentType: string | null;
  readonly declaredLength: number | null;
  readonly contentDisposition: string | null;
  readonly bytes: number;
  readonly sha256: string;
  /** The first bytes, for type detection. */
  readonly head: Buffer;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Validates one hop's URL against the source policy. Throws a non-retryable DownloadError. */
export function checkUrl(raw: string, policy: FetchPolicy, hops: DownloadHop[], redirect: boolean): URL {
  const code = redirect ? 'invalid-redirect' : 'url-not-allowed';
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new DownloadError(code, 'The URL is not valid', false, { hops });
  }
  if (url.protocol !== 'https:') {
    throw new DownloadError(code, `Only https is allowed, not ${url.protocol}`, false, { hops });
  }
  if (url.username !== '' || url.password !== '') {
    throw new DownloadError(code, 'URLs with credentials are not allowed', false, { hops });
  }
  const host = url.hostname.toLowerCase();
  if (isIP(host.replace(/^\[|\]$/g, '')) !== 0) {
    throw new DownloadError('host-not-allowed', 'IP address literals are not allowed', false, {
      hops,
    });
  }
  if (!policy.allowedHosts.includes(host)) {
    throw new DownloadError('host-not-allowed', `${host} is not on the source allowlist`, false, {
      hops,
    });
  }
  const port = url.port === '' ? 443 : Number(url.port);
  if (!policy.allowedPorts.includes(port)) {
    throw new DownloadError(code, `Port ${String(port)} is not allowed`, false, { hops });
  }
  url.hash = '';
  return url;
}

/** Hashes, counts and limits the stream and keeps its first bytes. */
class Meter extends Transform {
  readonly hash = createHash('sha256');
  bytes = 0;
  private readonly headChunks: Buffer[] = [];
  private headBytes = 0;

  constructor(private readonly maxBytes: number) {
    super();
  }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    this.bytes += chunk.length;
    if (this.bytes > this.maxBytes) {
      callback(
        new DownloadError(
          'size-limit-exceeded',
          `The response exceeds the limit of ${String(this.maxBytes)} bytes`,
          false,
        ),
      );
      return;
    }
    if (this.headBytes < SNIFF_BYTES) {
      const part = chunk.subarray(0, SNIFF_BYTES - this.headBytes);
      this.headChunks.push(Buffer.from(part));
      this.headBytes += part.length;
    }
    this.hash.update(chunk);
    callback(null, chunk);
  }

  head(): Buffer {
    return Buffer.concat(this.headChunks);
  }
}

const NETWORK_RETRYABLE = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ETIMEDOUT',
  'EPIPE',
  'ECONNABORTED',
  'EAI_AGAIN',
]);

function errorCode(error: unknown): string | undefined {
  return typeof error === 'object' && error !== null && 'code' in error
    ? String((error as { code: unknown }).code)
    : undefined;
}

/** Maps a low-level failure to a DownloadError (already-mapped errors pass through). */
function classify(error: unknown, signal: AbortSignal, deadline: AbortSignal): DownloadError {
  if (error instanceof DownloadError) return error;
  if (deadline.aborted) {
    return new DownloadError('timeout', 'The download exceeded its time limit', true, {}, { cause: error });
  }
  if (signal.aborted) {
    return new DownloadError('timeout', 'The download was aborted', true, {}, { cause: error });
  }
  const code = errorCode(error);
  const message = error instanceof Error ? error.message : String(error);
  if (code !== undefined && /^(ERR_TLS|CERT_|UNABLE_TO|DEPTH_ZERO|SELF_SIGNED|ERR_SSL|HOSTNAME_MISMATCH)/.test(code)) {
    return new DownloadError('tls-failure', `TLS verification failed: ${message}`, false, {}, { cause: error });
  }
  if (code !== undefined && NETWORK_RETRYABLE.has(code)) {
    return new DownloadError('connect-failed', `Network error: ${message}`, true, {}, { cause: error });
  }
  return new DownloadError('connect-failed', `Request failed: ${message}`, true, {}, { cause: error });
}

/**
 * Downloads one URL to a file with SSRF protection:
 * - https only, no credentials, no IP literals, hosts and ports from the source allowlist;
 * - every DNS answer is checked against the address policy before connecting, and the socket
 *   is pinned to a checked address (no second resolution, so DNS rebinding cannot swap it);
 * - redirects are followed manually and every hop is validated again from scratch;
 * - connect, idle and total timeouts, a declared and an enforced size limit;
 * - no content decoding (`Accept-Encoding: identity`; other encodings are refused).
 *
 * The body streams through a hash into the destination file; it is never buffered in memory,
 * interpreted, decompressed or executed.
 */
export class SafeFetcher {
  private readonly resolver: Resolver;

  constructor(private readonly options: SafeFetcherOptions) {
    this.resolver = options.resolver ?? systemResolver;
  }

  async fetchToFile(
    url: string,
    policy: FetchPolicy,
    destination: string,
    signal: AbortSignal,
  ): Promise<FetchResult> {
    const deadline = AbortSignal.timeout(this.options.totalTimeoutMs);
    const combined = AbortSignal.any([signal, deadline]);
    const hops: DownloadHop[] = [];
    let bytesReceived = 0;
    let httpStatus: number | null = null;
    try {
      let current = checkUrl(url, policy, hops, false);
      for (let redirects = 0; ; redirects += 1) {
        const hop: DownloadHop = {
          url: current.href,
          resolvedAddresses: [],
          connectedAddress: null,
          status: null,
          location: null,
        };
        hops.push(hop);
        const target = await this.resolve(current.hostname, hop, hops);
        const response = await this.request(current, target, combined);
        httpStatus = response.statusCode ?? null;
        hop.status = httpStatus;
        hop.connectedAddress = response.socket.remoteAddress ?? target.address;
        if (hop.connectedAddress !== target.address) {
          response.destroy();
          throw new DownloadError('address-blocked', 'The connection was not pinned to the checked address', false);
        }

        if (httpStatus !== null && REDIRECT_STATUSES.has(httpStatus)) {
          const location = response.headers.location ?? null;
          hop.location = location;
          response.resume();
          if (location === null) {
            throw new DownloadError('invalid-redirect', 'A redirect without a Location header', false);
          }
          if (redirects + 1 > this.options.maxRedirects) {
            throw new DownloadError(
              'too-many-redirects',
              `More than ${String(this.options.maxRedirects)} redirects`,
              false,
            );
          }
          let next: string;
          try {
            next = new URL(location, current).href;
          } catch {
            throw new DownloadError('invalid-redirect', 'The redirect target is not a valid URL', false);
          }
          current = checkUrl(next, policy, hops, true);
          continue;
        }

        if (httpStatus !== 200) {
          response.resume();
          throw httpFailure(httpStatus);
        }
        const encoding = response.headers['content-encoding'];
        if (encoding !== undefined && encoding.trim().toLowerCase() !== 'identity') {
          response.destroy();
          throw new DownloadError(
            'unsupported-encoding',
            `Content-Encoding ${encoding} is refused (content is never decoded)`,
            false,
          );
        }
        const declaredContentType = response.headers['content-type'] ?? null;
        const type = essence(declaredContentType) ?? 'application/octet-stream';
        if (!policy.allowedContentTypes.includes(type)) {
          response.destroy();
          throw new DownloadError(
            'content-type-not-allowed',
            `Content-Type ${type} is not allowed for this source`,
            false,
          );
        }
        const lengthHeader = response.headers['content-length'];
        const declaredLength =
          lengthHeader !== undefined && /^\d{1,15}$/.test(lengthHeader) ? Number(lengthHeader) : null;
        if (declaredLength !== null && declaredLength > policy.maxBytes) {
          response.destroy();
          throw new DownloadError(
            'size-limit-exceeded',
            `The declared size ${String(declaredLength)} exceeds the limit of ${String(policy.maxBytes)} bytes`,
            false,
          );
        }

        const meter = new Meter(policy.maxBytes);
        try {
          await pipeline(
            response,
            meter,
            createWriteStream(destination, { flags: 'wx', mode: 0o600 }),
            { signal: combined },
          );
        } finally {
          bytesReceived = meter.bytes;
        }
        if (declaredLength !== null && meter.bytes !== declaredLength) {
          throw new DownloadError(
            'size-mismatch',
            `Received ${String(meter.bytes)} bytes, the server declared ${String(declaredLength)}`,
            true,
          );
        }
        if (meter.bytes === 0) {
          throw new DownloadError('empty-response', 'The response body is empty', false);
        }
        return {
          hops,
          finalUrl: current.href,
          httpStatus,
          declaredContentType,
          declaredLength,
          contentDisposition: response.headers['content-disposition'] ?? null,
          bytes: meter.bytes,
          sha256: meter.hash.digest('hex'),
          head: meter.head(),
        };
      }
    } catch (error) {
      const mapped = classify(error, signal, deadline);
      throw new DownloadError(
        mapped.code,
        mapped.message,
        mapped.retryable,
        { hops, httpStatus, bytesReceived: Math.max(bytesReceived, mapped.bytesReceived) },
        { cause: error },
      );
    }
  }

  private async resolve(hostname: string, hop: DownloadHop, hops: DownloadHop[]): Promise<ResolvedAddress> {
    let answers: readonly ResolvedAddress[];
    try {
      answers = await this.resolver(hostname);
    } catch (error) {
      throw new DownloadError('dns-failure', `DNS resolution of ${hostname} failed`, true, { hops }, { cause: error });
    }
    hop.resolvedAddresses = answers.map((answer) => answer.address);
    if (answers.length === 0) {
      throw new DownloadError('dns-failure', `${hostname} has no addresses`, true, { hops });
    }
    // Every answer must be public: a mixed answer is a rebinding attempt or a misconfiguration.
    for (const answer of answers) {
      const check = this.options.addressPolicy.check(answer.address);
      if (!check.allowed) {
        throw new DownloadError(
          'address-blocked',
          `${hostname} resolves to a blocked address: ${check.reason ?? answer.address}`,
          false,
          { hops },
        );
      }
    }
    const [first] = answers;
    if (first === undefined) throw new DownloadError('dns-failure', `${hostname} has no addresses`, true, { hops });
    return first;
  }

  private request(url: URL, target: ResolvedAddress, signal: AbortSignal): Promise<IncomingMessage> {
    const { options } = this;
    // The socket connects to the address checked above, whatever the system resolver would say.
    const pinned: LookupFunction = (_hostname, lookupOptions, callback) => {
      if (lookupOptions.all === true) {
        callback(null, [{ address: target.address, family: target.family }]);
      } else {
        callback(null, target.address, target.family);
      }
    };
    return new Promise<IncomingMessage>((resolve, reject) => {
      const req = httpsRequest(
        {
          protocol: 'https:',
          host: url.hostname,
          servername: url.hostname,
          port: url.port === '' ? 443 : Number(url.port),
          path: `${url.pathname}${url.search}`,
          method: 'GET',
          headers: {
            accept: '*/*',
            'accept-encoding': 'identity',
            'user-agent': options.userAgent,
          },
          lookup: pinned,
          agent: false,
          signal,
          ...(options.ca === undefined ? {} : { ca: options.ca }),
        },
        (response) => {
          clearTimeout(connectTimer);
          resolve(response);
        },
      );
      const connectTimer = setTimeout(() => {
        req.destroy(new DownloadError('timeout', 'The source did not respond in time', true));
      }, options.connectTimeoutMs);
      req.setTimeout(options.idleTimeoutMs, () => {
        req.destroy(new DownloadError('timeout', 'The source stopped sending data', true));
      });
      req.on('error', (error) => {
        clearTimeout(connectTimer);
        reject(error);
      });
      req.end();
    });
  }
}

function httpFailure(status: number | null): DownloadError {
  const label = status === null ? 'no status' : `HTTP ${String(status)}`;
  if (status === 429) return new DownloadError('rate-limited', `The source answered ${label}`, true, { httpStatus: status });
  if (status === 408 || (status !== null && status >= 500)) {
    return new DownloadError('http-error', `The source answered ${label}`, true, { httpStatus: status });
  }
  return new DownloadError('http-error', `The source answered ${label}`, false, { httpStatus: status });
}
