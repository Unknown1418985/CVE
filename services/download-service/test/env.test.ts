import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { EnvValidationError } from '@cve/config';
import { buildServiceTestEnv } from '@cve/testing';

import { loadServiceEnv } from '../src/config/env.js';
import { buildSourcePolicies } from '../src/download/source-catalog.js';
import { SERVICE_NAME } from '../src/service.js';
import { downloadTestEnv } from './support.js';

describe('download-service environment', () => {
  it('uses the registered default port and safe defaults', () => {
    const env = downloadTestEnv();
    expect(env.PORT).toBe(4006);
    expect(env.DOWNLOAD_SOURCES_ENABLED).toEqual(['github-archive']);
    expect(env.SCAN_REQUIRED_SCANNERS).toEqual(['clamav', 'yara']);
    expect(env.DOWNLOAD_MAX_BYTES).toBe(100 * 1024 * 1024);
  });

  it('fails fast when required variables are missing', () => {
    expect(() => loadServiceEnv({})).toThrow(EnvValidationError);
  });

  it("refuses another service's database", () => {
    expect(() =>
      loadServiceEnv(
        buildServiceTestEnv(SERVICE_NAME, {
          KEYCLOAK_URL: 'http://keycloak.test/auth',
          KEYCLOAK_PUBLIC_URL: 'http://keycloak.test/auth',
          DATABASE_URL: 'postgresql://other_service:pw@127.0.0.1:5432/other_service',
        }),
      ),
    ).toThrow(/must connect to its own database/);
  });

  it('refuses unknown sources and scanners', () => {
    expect(() => downloadTestEnv({ DOWNLOAD_SOURCES_ENABLED: 'github-archive,pastebin' })).toThrow(
      /not approved download sources: pastebin/,
    );
    expect(() => downloadTestEnv({ SCAN_REQUIRED_SCANNERS: 'virustotal' })).toThrow(
      /not approved scanners/,
    );
  });

  it('requires automatic sources to be enabled', () => {
    expect(() =>
      downloadTestEnv({
        DOWNLOAD_SOURCES_ENABLED: 'github-archive',
        DOWNLOAD_AUTOMATIC_SOURCES: 'exploit-db',
      }),
    ).toThrow(/automatic sources must be enabled/);
  });

  it('accepts only https source origins without credentials or paths', () => {
    for (const value of [
      'http://codeload.github.com',
      'https://u:p@codeload.github.com',
      'https://codeload.github.com/x',
    ]) {
      expect(() => downloadTestEnv({ DOWNLOAD_GITHUB_ARCHIVE_URL: value })).toThrow(
        EnvValidationError,
      );
    }
    expect(() =>
      downloadTestEnv({
        NODE_ENV: 'production',
        DOWNLOAD_GITHUB_ARCHIVE_URL: 'https://codeload.github.com:8443',
      }),
    ).toThrow(/default https port/);
  });

  it('builds host allowlists from the base URL plus configured extras', () => {
    const sources = buildSourcePolicies(
      downloadTestEnv({
        DOWNLOAD_SOURCES_ENABLED: 'github-archive,exploit-db',
        DOWNLOAD_AUTOMATIC_SOURCES: 'github-archive',
      }),
    );
    expect(sources.find((s) => s.source === 'github-archive')?.allowedHosts).toEqual([
      'codeload.github.com',
    ]);
    expect(sources.find((s) => s.source === 'exploit-db')).toMatchObject({
      enabled: true,
      automatic: false,
      allowedHosts: ['www.exploit-db.com', 'exploit-db.com'],
    });
    expect(() => downloadTestEnv({ DOWNLOAD_GITHUB_ARCHIVE_EXTRA_HOSTS: '10.0.0.1' })).toThrow(
      EnvValidationError,
    );
  });

  it('requires an absolute scanner binary and resolves a relative rules path', () => {
    expect(() => downloadTestEnv({ YARA_BINARY: 'yara' })).toThrow(/absolute path/);
    expect(downloadTestEnv({ YARA_RULES_PATH: 'rules.yar' }).YARA_RULES_PATH).toBe(
      resolve('rules.yar'),
    );
  });
});
