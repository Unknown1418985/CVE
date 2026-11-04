import { Writable } from 'node:stream';

import { describe, expect, it } from 'vitest';

import { createLogger, PinoNestLogger, REDACTED_VALUE } from './index.js';

function captureLogger() {
  const lines: Record<string, unknown>[] = [];
  const destination = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      lines.push(JSON.parse(chunk.toString()) as Record<string, unknown>);
      callback();
    },
  });
  const logger = createLogger({ service: 'test-service', level: 'trace', destination });
  return { logger, lines };
}

describe('createLogger', () => {
  it('writes structured JSON with service, level label and ISO time', () => {
    const { logger, lines } = captureLogger();
    logger.info({ cveId: 'CVE-2026-0001' }, 'hello');
    expect(lines[0]).toMatchObject({
      service: 'test-service',
      level: 'info',
      message: 'hello',
      cveId: 'CVE-2026-0001',
    });
    expect(typeof lines[0]!['time']).toBe('string');
  });

  it('redacts secrets', () => {
    const { logger, lines } = captureLogger();
    logger.info(
      {
        req: { headers: { authorization: 'Bearer abc', cookie: 'sid=1' } },
        credentials: { password: 'p', apiKey: 'k' },
      },
      'request',
    );
    const record = lines[0] as {
      req: { headers: Record<string, string> };
      credentials: Record<string, string>;
    };
    expect(record.req.headers['authorization']).toBe(REDACTED_VALUE);
    expect(record.req.headers['cookie']).toBe(REDACTED_VALUE);
    expect(record.credentials['password']).toBe(REDACTED_VALUE);
    expect(record.credentials['apiKey']).toBe(REDACTED_VALUE);
  });
});

describe('PinoNestLogger', () => {
  it('maps Nest levels and extracts context', () => {
    const { logger, lines } = captureLogger();
    const nestLogger = new PinoNestLogger(logger);
    nestLogger.log('started', 'Bootstrap');
    nestLogger.verbose('details', 'Module');
    nestLogger.error('failed', 'Error: boom\n    at x', 'Handler');

    expect(lines[0]).toMatchObject({ level: 'info', message: 'started', context: 'Bootstrap' });
    expect(lines[1]).toMatchObject({ level: 'trace', message: 'details', context: 'Module' });
    expect(lines[2]).toMatchObject({
      level: 'error',
      message: 'failed',
      context: 'Handler',
      stack: 'Error: boom\n    at x',
    });
  });
});
