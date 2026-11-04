import type { RequestHandler } from 'express';
import helmet, { type HelmetOptions } from 'helmet';

/** Strict defaults for JSON APIs: no content may be loaded or framed. */
export const API_HELMET_OPTIONS: Readonly<HelmetOptions> = {
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'no-referrer' },
  strictTransportSecurity: { maxAge: 63_072_000, includeSubDomains: true, preload: false },
  xFrameOptions: { action: 'deny' },
};

/** Relaxed CSP that the bundled Swagger UI needs (inline styles and scripts from self). */
export const DOCS_HELMET_OPTIONS: Readonly<HelmetOptions> = {
  ...API_HELMET_OPTIONS,
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      frameAncestors: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'none'"],
    },
  },
};

export interface SecurityHeadersOptions {
  /** Path prefixes (e.g. `/api/v1/docs`) served with the relaxed documentation policy. */
  readonly docsPathPrefixes?: readonly string[];
}

export function createSecurityHeadersMiddleware(
  options: SecurityHeadersOptions = {},
): RequestHandler {
  const strict = helmet(API_HELMET_OPTIONS);
  const docs = helmet(DOCS_HELMET_OPTIONS);
  const prefixes = options.docsPathPrefixes ?? [];

  return (req, res, next) => {
    const useDocsPolicy = prefixes.some((prefix) => req.path.startsWith(prefix));
    (useDocsPolicy ? docs : strict)(req, res, next);
  };
}
