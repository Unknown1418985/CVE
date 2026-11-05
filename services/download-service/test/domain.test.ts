import { describe, expect, it } from 'vitest';

import {
  aggregateScanStatus,
  checkLifecycleChange,
  combineVerification,
  isReleasable,
  mustRevokeRelease,
} from '../src/domain/artifact-rules.js';
import { detectFileType, riskIndicators } from '../src/domain/file-type.js';
import { AddressPolicy, embeddedIpv4 } from '../src/domain/ip-policy.js';
import {
  filenameFromContentDisposition,
  filenameFromUrl,
  quarantineKey,
  releasedKey,
  sanitizeFilename,
} from '../src/domain/naming.js';
import {
  exploitDbIdFromReference,
  githubArchiveTarget,
  resolveUserUrl,
} from '../src/domain/sources.js';
import { buildSourcePolicies } from '../src/download/source-catalog.js';
import { downloadTestEnv } from './support.js';

const SHA = 'a'.repeat(40);

describe('address policy (SSRF)', () => {
  const policy = new AddressPolicy();

  it.each([
    '127.0.0.1',
    '10.1.2.3',
    '172.16.0.1',
    '172.31.255.254',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '0.0.0.0',
    '192.0.2.10',
    '198.18.0.1',
    '224.0.0.1',
    '255.255.255.255',
    '240.0.0.1',
    '::1',
    '::',
    'fe80::1',
    'fc00::1',
    'fd12:3456::1',
    'ff02::1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '::ffff:10.0.0.1',
    '64:ff9b::a00:1',
    '2002:7f00:1::',
    '2001:db8::1',
    '2001:0:4136:e378:8000:63bf:3fff:fdd2',
  ])('blocks %s', (address) => {
    expect(policy.check(address).allowed).toBe(false);
  });

  it.each(['140.82.112.3', '185.199.108.133', '8.8.8.8', '2606:4700::1111', '2a01:4f8::1'])(
    'allows the public address %s',
    (address) => {
      expect(policy.check(address).allowed).toBe(true);
    },
  );

  it('refuses things that are not IP addresses', () => {
    expect(policy.check('localhost').allowed).toBe(false);
    expect(policy.check('').allowed).toBe(false);
  });

  it('extracts IPv4 addresses embedded in IPv6', () => {
    expect(embeddedIpv4('::ffff:127.0.0.1')).toContain('127.0.0.1');
    expect(embeddedIpv4('64:ff9b::0a00:0001')).toContain('10.0.0.1');
    expect(embeddedIpv4('2002:c0a8:0101::')).toContain('192.168.1.1');
  });

  it('honours explicit exceptions only', () => {
    const withException = new AddressPolicy(['127.0.0.1/32']);
    expect(withException.check('127.0.0.1').allowed).toBe(true);
    expect(withException.check('127.0.0.2').allowed).toBe(false);
    expect(() => new AddressPolicy(['not-an-ip'])).toThrow(/Invalid address exception/);
  });
});

describe('source URLs', () => {
  const sources = buildSourcePolicies(
    downloadTestEnv({ DOWNLOAD_SOURCES_ENABLED: 'github-archive,exploit-db' }),
  );
  const github = sources.find((source) => source.source === 'github-archive');
  const exploitDb = sources.find((source) => source.source === 'exploit-db');
  if (github === undefined || exploitDb === undefined) throw new Error('sources missing');

  it('builds canonical archive URLs only for valid names and full commit SHAs', () => {
    expect(githubArchiveTarget(github, 'zz-test/poc', SHA)?.url).toBe(
      `https://codeload.github.com/zz-test/poc/tar.gz/${SHA}`,
    );
    expect(githubArchiveTarget(github, 'zz-test/poc', 'main')).toBeNull();
    expect(githubArchiveTarget(github, '../etc', SHA)).toBeNull();
    expect(githubArchiveTarget(github, 'zz-test/..', SHA)).toBeNull();
    expect(githubArchiveTarget(github, 'a/b/c', SHA)).toBeNull();
  });

  it('maps user URLs of enabled sources to canonical targets', () => {
    expect(resolveUserUrl(sources, `https://github.com/zz-test/poc/archive/${SHA}.tar.gz`)?.url).toBe(
      `https://codeload.github.com/zz-test/poc/tar.gz/${SHA}`,
    );
    expect(resolveUserUrl(sources, `https://github.com/zz-test/poc/commit/${SHA}`)?.source).toBe(
      'github-archive',
    );
    expect(resolveUserUrl(sources, 'https://www.exploit-db.com/exploits/12345')?.url).toBe(
      'https://www.exploit-db.com/download/12345',
    );
    expect(resolveUserUrl(sources, 'https://exploit-db.com/raw/9')?.url).toBe(
      'https://www.exploit-db.com/download/9',
    );
  });

  it('refuses mutable references, other hosts, credentials and plain http', () => {
    for (const url of [
      'https://github.com/zz-test/poc/archive/refs/heads/main.tar.gz',
      'https://github.com/zz-test/poc/archive/main.tar.gz',
      'http://github.com/zz-test/poc/commit/' + SHA,
      `https://user:pw@github.com/zz-test/poc/commit/${SHA}`,
      'https://evil.test/download/1',
      'https://127.0.0.1/download/1',
      'https://www.exploit-db.com/exploits/0',
      'https://www.exploit-db.com/exploits/1/../../x',
      'not a url',
    ]) {
      expect(resolveUserUrl(sources, url)).toBeNull();
    }
  });

  it('ignores disabled sources', () => {
    const githubOnly = buildSourcePolicies(downloadTestEnv());
    expect(resolveUserUrl(githubOnly, 'https://www.exploit-db.com/exploits/12345')).toBeNull();
  });

  it('extracts Exploit-DB IDs from CVE references, including old http links', () => {
    expect(exploitDbIdFromReference(exploitDb, 'http://www.exploit-db.com/exploits/4242')).toBe('4242');
    expect(exploitDbIdFromReference(exploitDb, 'https://www.exploit-db.com/search?q=x')).toBeNull();
  });
});

describe('file type detection', () => {
  const cases: [string, Buffer, string][] = [
    ['gzip', Buffer.from([0x1f, 0x8b, 0x08, 0x00]), 'gzip'],
    ['zip', Buffer.from('PK\x03\x04rest', 'latin1'), 'zip'],
    ['pe', Buffer.from('MZ\x90\x00', 'latin1'), 'pe-executable'],
    ['elf', Buffer.from('\x7fELF\x02', 'latin1'), 'elf-executable'],
    ['pdf', Buffer.from('%PDF-1.7'), 'pdf'],
    ['ole', Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), 'ole-document'],
    ['script', Buffer.from('#!/bin/sh\necho hi\n'), 'script'],
    ['text', Buffer.from('int main(void) { return 0; }\n'), 'text'],
    ['binary', Buffer.from([0x00, 0x01, 0x02, 0x03, 0xff]), 'binary'],
  ];
  it.each(cases)('recognises %s from magic bytes', (_name, head, expected) => {
    expect(detectFileType(head, head.length)).toBe(expected);
  });

  it('recognises empty content and tar headers', () => {
    expect(detectFileType(Buffer.alloc(0), 0)).toBe('empty');
    const tar = Buffer.alloc(512);
    tar.write('ustar', 257, 'latin1');
    expect(detectFileType(tar, 512)).toBe('tar');
  });

  it('derives risk indicators, including a declared type that does not match', () => {
    expect(riskIndicators('pe-executable', 'application/octet-stream')).toEqual(['executable']);
    expect(riskIndicators('gzip', 'application/x-gzip')).toEqual(['archive']);
    expect(riskIndicators('gzip', 'text/plain')).toEqual(['archive', 'content-type-mismatch']);
    expect(riskIndicators('ole-document', null)).toEqual(['macro-capable-document']);
  });
});

describe('names and object keys', () => {
  it('reduces source-provided names to a display string', () => {
    expect(sanitizeFilename('../../etc/passwd')).toBe('passwd');
    expect(sanitizeFilename('..\\..\\win.ini')).toBe('win.ini');
    expect(sanitizeFilename('evil‮gpj.exe')).toBe('evilgpj.exe');
    expect(sanitizeFilename('.hidden')).toBe('hidden');
    expect(sanitizeFilename('..')).toBeNull();
    expect(sanitizeFilename('a'.repeat(300))).toHaveLength(255);
  });

  it('parses Content-Disposition and URL names', () => {
    expect(filenameFromContentDisposition('attachment; filename=poc-main.tar.gz')).toBe('poc-main.tar.gz');
    expect(filenameFromContentDisposition('attachment; filename="a \\"b\\".txt"')).toBe('a "b".txt');
    expect(filenameFromContentDisposition("attachment; filename*=UTF-8''%2E%2E%2Fx.sh")).toBe('x.sh');
    expect(filenameFromUrl('https://codeload.github.com/o/r/tar.gz/abc')).toBe('abc');
  });

  it('generates object keys from UUIDs only', () => {
    const id = '0b0f5a0c-1111-4222-8333-444455556666';
    expect(quarantineKey(id, new Date('2026-03-04T00:00:00Z'))).toBe(`quarantine/2026/03/${id}`);
    expect(releasedKey(id)).toBe(`released/${id}`);
    expect(() => quarantineKey('../x', new Date())).toThrow();
  });
});

describe('scan and lifecycle rules', () => {
  const required = ['clamav', 'yara'] as const;

  it('is clean only when every required scanner ran cleanly', () => {
    expect(
      aggregateScanStatus(
        [
          { scanner: 'clamav', verdict: 'clean' },
          { scanner: 'yara', verdict: 'clean' },
        ],
        required,
      ),
    ).toBe('clean');
    expect(aggregateScanStatus([{ scanner: 'clamav', verdict: 'clean' }], required)).toBe('incomplete');
    expect(
      aggregateScanStatus(
        [
          { scanner: 'clamav', verdict: 'clean' },
          { scanner: 'yara', verdict: 'error' },
        ],
        required,
      ),
    ).toBe('incomplete');
    expect(
      aggregateScanStatus(
        [
          { scanner: 'clamav', verdict: 'clean' },
          { scanner: 'yara', verdict: 'not-configured' },
        ],
        required,
      ),
    ).toBe('incomplete');
    expect(aggregateScanStatus([], [])).toBe('incomplete');
  });

  it('lets findings win over everything else', () => {
    expect(
      aggregateScanStatus(
        [
          { scanner: 'clamav', verdict: 'malicious' },
          { scanner: 'yara', verdict: 'suspicious' },
        ],
        required,
      ),
    ).toBe('malicious');
    expect(
      aggregateScanStatus(
        [
          { scanner: 'clamav', verdict: 'error' },
          { scanner: 'yara', verdict: 'suspicious' },
        ],
        required,
      ),
    ).toBe('suspicious');
  });

  it('combines PoC verification with the most severe judgement winning', () => {
    expect(combineVerification([])).toBe('unverified');
    expect(combineVerification(['verified', 'verified'])).toBe('verified');
    expect(combineVerification(['verified', 'unverified'])).toBe('unverified');
    expect(combineVerification(['verified', 'malicious', 'in-review'])).toBe('malicious');
  });

  it('never releases what is not clean, and revokes releases that stop qualifying', () => {
    const clean = { lifecycleStatus: 'quarantined', scanStatus: 'clean', verificationStatus: 'unverified' } as const;
    expect(isReleasable(clean)).toBe(true);
    expect(checkLifecycleChange(clean, 'released')).toBeNull();
    for (const scanStatus of ['pending', 'scanning', 'suspicious', 'malicious', 'incomplete', 'integrity-failure'] as const) {
      expect(checkLifecycleChange({ ...clean, scanStatus }, 'released')).toMatch(/scan status/);
    }
    expect(checkLifecycleChange({ ...clean, verificationStatus: 'malicious' }, 'released')).toMatch(/malicious/);
    expect(checkLifecycleChange({ ...clean, lifecycleStatus: 'rejected' }, 'released')).toMatch(/cannot change/);
    expect(mustRevokeRelease({ ...clean, lifecycleStatus: 'released', scanStatus: 'malicious' })).toBe(true);
    expect(mustRevokeRelease({ ...clean, lifecycleStatus: 'released' })).toBe(false);
  });
});
