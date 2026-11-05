import type { DownloadSource, DownloadSourceStatus } from '@cve/contracts';

import type { Env } from '../config/env.js';
import type { SourcePolicy } from '../domain/sources.js';
import type { FetchPolicy } from './safe-fetcher.js';

const DESCRIPTIONS: Readonly<
  Record<DownloadSource, { name: string; description: string; termsUrl: string | null }>
> = {
  'github-archive': {
    name: 'GitHub repository archives',
    description:
      'Gzip tarball of a public GitHub repository at a fixed commit (immutable content). Stored as is: never extracted.',
    termsUrl: 'https://docs.github.com/en/site-policy/github-terms/github-terms-of-service',
  },
  'exploit-db': {
    name: 'Exploit-DB',
    description:
      'Raw exploit file of an Exploit-DB entry. Check the Exploit-DB terms before enabling it.',
    termsUrl: 'https://www.exploit-db.com/terms',
  },
};

/** Source policies of this deployment, built from configuration at startup. */
export function buildSourcePolicies(env: Env): SourcePolicy[] {
  const policy = (
    source: DownloadSource,
    baseUrl: string,
    extraHosts: readonly string[],
    contentTypes: readonly string[],
    fileTypes: SourcePolicy['allowedFileTypes'],
  ): SourcePolicy => {
    const base = new URL(baseUrl);
    return {
      source,
      ...DESCRIPTIONS[source],
      enabled: env.DOWNLOAD_SOURCES_ENABLED.includes(source),
      automatic: env.DOWNLOAD_AUTOMATIC_SOURCES.includes(source),
      baseUrl: base,
      allowedHosts: [...new Set([base.hostname.toLowerCase(), ...extraHosts])],
      allowedContentTypes: contentTypes,
      allowedFileTypes: fileTypes,
      maxBytes: env.DOWNLOAD_MAX_BYTES,
    };
  };
  return [
    policy(
      'github-archive',
      env.DOWNLOAD_GITHUB_ARCHIVE_URL,
      env.DOWNLOAD_GITHUB_ARCHIVE_EXTRA_HOSTS,
      ['application/x-gzip', 'application/gzip', 'application/octet-stream'],
      ['gzip'],
    ),
    policy(
      'exploit-db',
      env.DOWNLOAD_EXPLOIT_DB_URL,
      env.DOWNLOAD_EXPLOIT_DB_EXTRA_HOSTS,
      ['text/plain', 'application/octet-stream', 'application/x-sh', 'text/x-c', 'text/html'],
      ['text', 'script', 'gzip', 'zip', 'tar', 'binary', 'pdf'],
    ),
  ];
}

export function fetchPolicyFor(policy: SourcePolicy): FetchPolicy {
  return {
    allowedHosts: policy.allowedHosts,
    allowedPorts: [policy.baseUrl.port === '' ? 443 : Number(policy.baseUrl.port)],
    allowedContentTypes: policy.allowedContentTypes,
    maxBytes: policy.maxBytes,
  };
}

export function sourceStatus(policy: SourcePolicy): DownloadSourceStatus {
  return {
    source: policy.source,
    name: policy.name,
    description: policy.description,
    enabled: policy.enabled,
    automatic: policy.automatic,
    allowedHosts: [...policy.allowedHosts],
    allowedFileTypes: [...policy.allowedFileTypes],
    allowedContentTypes: [...policy.allowedContentTypes],
    maxBytes: policy.maxBytes,
    termsUrl: policy.termsUrl,
  };
}
