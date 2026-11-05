import { createHash } from 'node:crypto';

import type { ArtifactFile, RiskIndicator } from '@cve/contracts';

import { sanitizePath } from './text.js';

/** One entry of a repository tree listing (metadata only; contents are never fetched). */
export interface TreeEntry {
  readonly path: string;
  readonly mode: string;
  readonly type: 'blob' | 'tree' | 'commit';
  readonly sha: string;
  readonly size: number | null;
}

export type FileCategory = ArtifactFile['category'];

const SOURCE_EXTENSIONS = new Set([
  'asm',
  'asp',
  'aspx',
  'bash',
  'bat',
  'c',
  'cc',
  'cjs',
  'cmd',
  'cpp',
  'cs',
  'cxx',
  'dart',
  'go',
  'groovy',
  'h',
  'hpp',
  'htm',
  'html',
  'java',
  'js',
  'jsp',
  'jsx',
  'kt',
  'lua',
  'm',
  'mjs',
  'nim',
  'nse',
  'php',
  'pl',
  'pm',
  'ps1',
  'psm1',
  'py',
  'r',
  'rb',
  'rs',
  's',
  'scala',
  'sh',
  'sql',
  'swift',
  'ts',
  'tsx',
  'vb',
  'vbs',
  'yaml',
  'yml',
  'zig',
  'zsh',
]);
const SOURCE_NAMES = new Set(['dockerfile', 'makefile', 'cmakelists.txt', 'gemfile', 'rakefile']);
const DOCUMENT_EXTENSIONS = new Set([
  'gif',
  'jpeg',
  'jpg',
  'md',
  'pdf',
  'png',
  'rst',
  'svg',
  'txt',
  'webp',
  'mp4',
  'webm',
]);
const EXECUTABLE_EXTENSIONS = new Set([
  'apk',
  'appimage',
  'bin',
  'com',
  'deb',
  'dll',
  'dmg',
  'dylib',
  'elf',
  'exe',
  'jar',
  'ko',
  'msi',
  'o',
  'pkg',
  'rpm',
  'scr',
  'so',
  'sys',
  'war',
]);
const ARCHIVE_EXTENSIONS = new Set([
  '7z',
  'bz2',
  'cab',
  'gz',
  'iso',
  'rar',
  'tar',
  'tgz',
  'txz',
  'xz',
  'zip',
  'zst',
]);
const MACRO_DOCUMENT_EXTENSIONS = new Set([
  'doc',
  'docm',
  'dotm',
  'ppam',
  'ppt',
  'pptm',
  'xla',
  'xlam',
  'xls',
  'xlsm',
  'xltm',
]);

/** Files that are identical across thousands of unrelated repositories. */
const BOILERPLATE_NAMES =
  /^(?:license|licence|copying|unlicense)(?:\.[a-z]+)?$|^\.git(?:ignore|attributes|keep)$/i;
/** Git object ID of the empty blob. */
export const EMPTY_BLOB_SHA = 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391';

function basename(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1);
}

export function classifyPath(path: string): FileCategory {
  const name = basename(path).toLowerCase();
  if (SOURCE_NAMES.has(name)) return 'source';
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return 'other';
  const extension = name.slice(dot + 1);
  if (SOURCE_EXTENSIONS.has(extension)) return 'source';
  if (EXECUTABLE_EXTENSIONS.has(extension)) return 'executable';
  if (ARCHIVE_EXTENSIONS.has(extension)) return 'archive';
  if (MACRO_DOCUMENT_EXTENSIONS.has(extension)) return 'macro-document';
  if (DOCUMENT_EXTENSIONS.has(extension)) return 'document';
  return 'other';
}

/** Whether a file says nothing about what a repository contains (licences, empty files). */
export function isBoilerplate(entry: Pick<TreeEntry, 'path' | 'sha'>): boolean {
  return entry.sha === EMPTY_BLOB_SHA || BOILERPLATE_NAMES.test(basename(entry.path));
}

export interface SnapshotSummary {
  /** SHA-256 over the canonical listing; equal listings give equal fingerprints. */
  readonly fingerprint: string;
  readonly files: readonly ArtifactFile[];
  readonly fileCount: number;
  readonly totalBytes: number;
  readonly hasSourceCode: boolean;
  readonly riskIndicators: readonly RiskIndicator[];
  /** File and directory paths (sanitised), used to find CVE IDs in names. */
  readonly paths: readonly string[];
}

/**
 * Summarises a tree listing: fingerprint, per-file categories and metadata-only risk indicators.
 * `truncated` is true when the source or the service limit cut the listing.
 */
export function summarizeTree(
  entries: readonly TreeEntry[],
  options: { truncated: boolean; maxFiles: number },
): SnapshotSummary {
  const blobs = entries.filter((entry) => entry.type === 'blob');
  const canonical = [...entries]
    .filter((entry) => entry.type !== 'tree')
    .map((entry) => `${entry.mode} ${entry.type} ${entry.sha}\t${entry.path}`)
    .sort();
  const fingerprint = createHash('sha256').update(canonical.join('\n')).digest('hex');
  const files: ArtifactFile[] = blobs.slice(0, options.maxFiles).map((entry) => ({
    path: sanitizePath(entry.path),
    blobSha: entry.sha,
    sizeBytes: entry.size,
    category: classifyPath(entry.path),
  }));
  const categories = new Set(blobs.map((entry) => classifyPath(entry.path)));
  const hasSourceCode = categories.has('source');
  const risk: RiskIndicator[] = [];
  if (categories.has('executable')) risk.push('contains-executables');
  if (categories.has('archive')) risk.push('contains-archives');
  if (categories.has('macro-document')) risk.push('contains-macro-documents');
  if (blobs.length === 0) risk.push('empty');
  else if (!hasSourceCode) risk.push('no-source-code');
  const truncated = options.truncated || blobs.length > options.maxFiles;
  if (truncated) risk.push('listing-truncated');
  return {
    fingerprint,
    files,
    fileCount: blobs.length,
    totalBytes: blobs.reduce((sum, entry) => sum + (entry.size ?? 0), 0),
    hasSourceCode,
    riskIndicators: risk,
    paths: entries.slice(0, options.maxFiles * 2).map((entry) => sanitizePath(entry.path)),
  };
}

/**
 * Jaccard similarity of two sets of significant blobs. Boilerplate must already be excluded;
 * sets with fewer than two significant blobs are never considered similar.
 */
export function blobSimilarity(a: ReadonlySet<string>, b: ReadonlySet<string>): number {
  if (a.size < 2 || b.size < 2) return 0;
  let shared = 0;
  for (const sha of a) if (b.has(sha)) shared += 1;
  return shared / (a.size + b.size - shared);
}
