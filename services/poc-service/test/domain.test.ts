import { describe, expect, it } from 'vitest';

import { canTransitionVerification, type Permission } from '@cve/contracts';

import { mapGithubRepository } from '../src/connectors/github/github-mapping.js';
import { isNewer, scheduleAfterChange } from '../src/events/cve-tracker.js';
import {
  blobSimilarity,
  classifyPath,
  EMPTY_BLOB_SHA,
  isBoilerplate,
  summarizeTree,
  type TreeEntry,
} from '../src/domain/files.js';
import { classifyReference, parseGithubRepositoryUrl } from '../src/domain/references.js';
import { nextScanDelayMs } from '../src/domain/scan-policy.js';
import {
  collectMentions,
  confidenceLevel,
  scoreAssociation,
  SIGNAL_WEIGHTS,
  type PairEvidence,
  type RepositoryEvidence,
} from '../src/domain/scoring.js';
import { distinctCveIds, findCveMentions, sanitizePath, sanitizeText } from '../src/domain/text.js';
import { checkVerificationTransition } from '../src/domain/verification.js';
import { githubRepo, sha } from './support.js';

const NOW = new Date('2026-11-05T00:00:00Z');
const CVE = 'CVE-2026-90001';

const repo = (overrides: Partial<RepositoryEvidence> = {}): RepositoryEvidence => ({
  name: 'poc',
  description: null,
  topics: [],
  isFork: false,
  sourceCreatedAt: new Date('2026-03-01T00:00:00Z'),
  sizeKb: 10,
  snapshot: null,
  ...overrides,
});
const noPair: PairEvidence = { references: [], searchMatched: false, manual: false };

function score(evidence: RepositoryEvidence, pair: PairEvidence = noPair, cveId = CVE) {
  return scoreAssociation(cveId, evidence, collectMentions(evidence, NOW), pair);
}

describe('untrusted text', () => {
  it('removes control, bidirectional and zero-width characters and truncates', () => {
    expect(sanitizeText('  safe‮txt.exe\u0000 ​name\n\tok  ', 100)).toBe('safetxt.exe name ok');
    expect(sanitizeText('a'.repeat(20), 10)).toBe(`${'a'.repeat(9)}…`);
    expect(sanitizeText('\u0007​', 10)).toBeNull();
    expect(sanitizeText(null, 10)).toBeNull();
    expect(sanitizePath('dir/‮gnp.exe')).toBe('dir/gnp.exe');
  });

  it('finds CVE IDs in common spellings, but not inside other tokens', () => {
    const text = 'PoC for cve_2026_90001, CVE-2026-90002 and CVE 2026 90003; see CVE2026-90004.';
    expect(distinctCveIds(text, NOW)).toEqual([
      'CVE-2026-90001',
      'CVE-2026-90002',
      'CVE-2026-90003',
      'CVE-2026-90004',
    ]);
    expect(findCveMentions('XCVE-2026-90001 CVE-2026-900011234567 CVE-2026-0000', NOW)).toEqual([]);
    // Years outside the CVE program's range are refused.
    expect(findCveMentions('CVE-1980-1234 CVE-2099-1234', NOW)).toEqual([]);
  });
});

describe('association scoring', () => {
  it('scores a repository named after the CVE as medium, never as confirmed', () => {
    const result = score(repo({ name: `${CVE}-poc` }));
    expect(result.signals.map((signal) => signal.kind)).toEqual(['name']);
    expect(result.confidence).toBe(SIGNAL_WEIGHTS.name);
    expect(result.level).toBe('medium');
  });

  it('combines independent evidence with a noisy-OR', () => {
    const evidence = repo({
      name: CVE,
      topics: [CVE.toLowerCase()],
      description: `Exploit for ${CVE}`,
      snapshot: { paths: [`exploit_${CVE}.py`], fileCount: 2, hasSourceCode: true },
    });
    const result = score(evidence);
    expect(result.signals.map((signal) => signal.kind)).toEqual([
      'name',
      'topic',
      'description',
      'file-path',
    ]);
    expect(result.confidence).toBeCloseTo(1 - 0.45 * 0.6 * 0.75 * 0.65, 2);
    expect(result.level).toBe('high');
  });

  it('weighs a description claim alone low (descriptions are untrusted)', () => {
    const result = score(repo({ description: `Totally real working exploit for ${CVE}!!!` }));
    expect(result.confidence).toBe(0.25);
    expect(result.level).toBe('low');
    expect(result.signals[0]?.evidence).toContain(CVE);
  });

  it('a search hit without literal evidence stays below the storage threshold', () => {
    const result = score(repo(), { ...noPair, searchMatched: true });
    expect(result.signals.map((signal) => signal.kind)).toEqual(['search-match']);
    expect(result.confidence).toBe(0.05);
  });

  it('penalises collections, forks, empty repositories and repositories older than the CVE', () => {
    const many = Array.from(
      { length: 12 },
      (_, index) => `CVE-2026-${String(90_000 + index)}`,
    ).join(' ');
    const collection = score(repo({ name: CVE, description: many }));
    expect(collection.penalties.map((p) => p.kind)).toEqual(['multi-cve']);
    expect(collection.penalties[0]?.factor).toBe(0.25);
    expect(collection.confidence).toBeLessThan(0.25);

    const fork = score(repo({ name: CVE, isFork: true }));
    expect(fork.confidence).toBeCloseTo(0.55 * 0.85, 2);

    const empty = score(repo({ name: CVE, sizeKb: 0 }));
    expect(empty.penalties.map((p) => p.kind)).toEqual(['empty-repository']);
    expect(empty.confidence).toBeCloseTo(0.55 * 0.3, 2);

    const docs = score(
      repo({ name: CVE, snapshot: { paths: ['README.md'], fileCount: 1, hasSourceCode: false } }),
    );
    expect(docs.penalties.map((p) => p.kind)).toEqual(['no-source-code']);

    const old = score(repo({ name: CVE, sourceCreatedAt: new Date('2019-05-01T00:00:00Z') }));
    expect(old.penalties.map((p) => p.kind)).toEqual(['predates-cve']);
  });

  it('does not penalise curated evidence from CVE references', () => {
    const evidence = repo({ name: 'scanner', sizeKb: 0, isFork: true });
    const result = score(evidence, {
      references: [{ url: 'https://github.com/a/b', exploit: true }],
      searchMatched: false,
      manual: false,
    });
    expect(result.signals.map((s) => s.kind)).toEqual(['cve-exploit-reference']);
    expect(result.confidence).toBe(0.7);
    const plain = score(evidence, {
      references: [{ url: 'https://github.com/a/b', exploit: false }],
      searchMatched: false,
      manual: false,
    });
    expect(plain.signals.map((s) => s.kind)).toEqual(['cve-reference']);
  });

  it('caps automatic confidence below 1', () => {
    const result = score(repo({ name: CVE, topics: [CVE.toLowerCase()] }), {
      references: [{ url: 'https://github.com/a/b', exploit: true }],
      searchMatched: true,
      manual: true,
    });
    expect(result.confidence).toBe(0.99);
  });

  it('maps scores to levels', () => {
    expect(confidenceLevel(0.7)).toBe('high');
    expect(confidenceLevel(0.4)).toBe('medium');
    expect(confidenceLevel(0.39)).toBe('low');
  });
});

describe('file listings', () => {
  const entry = (path: string, seed: string, size = 10): TreeEntry => ({
    path,
    mode: '100644',
    type: 'blob',
    sha: sha(seed),
    size,
  });

  it('classifies files by name only (contents are never read)', () => {
    expect(classifyPath('src/exploit.py')).toBe('source');
    expect(classifyPath('Dockerfile')).toBe('source');
    expect(classifyPath('payload.EXE')).toBe('executable');
    expect(classifyPath('poc.7z')).toBe('archive');
    expect(classifyPath('invoice.docm')).toBe('macro-document');
    expect(classifyPath('README.md')).toBe('document');
    expect(classifyPath('.env')).toBe('other');
  });

  it('fingerprints a listing independently of entry order', () => {
    const a = [entry('a.py', 'a'), entry('b/c.sh', 'b')];
    const first = summarizeTree(a, { truncated: false, maxFiles: 100 });
    const second = summarizeTree([...a].reverse(), { truncated: false, maxFiles: 100 });
    expect(first.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(first.fingerprint).toBe(second.fingerprint);
    expect(
      summarizeTree([entry('a.py', 'z'), entry('b/c.sh', 'b')], { truncated: false, maxFiles: 100 })
        .fingerprint,
    ).not.toBe(first.fingerprint);
  });

  it('derives risk indicators from the listing', () => {
    const summary = summarizeTree(
      [entry('readme.md', 'r'), entry('run.exe', 'x'), entry('kit.zip', 'z')],
      {
        truncated: false,
        maxFiles: 100,
      },
    );
    expect(summary.riskIndicators).toEqual([
      'contains-executables',
      'contains-archives',
      'no-source-code',
    ]);
    expect(summary.hasSourceCode).toBe(false);
    expect(summarizeTree([], { truncated: false, maxFiles: 10 }).riskIndicators).toEqual(['empty']);
    const capped = summarizeTree([entry('a.py', 'a'), entry('b.py', 'b'), entry('c.py', 'c')], {
      truncated: false,
      maxFiles: 2,
    });
    expect(capped.files).toHaveLength(2);
    expect(capped.fileCount).toBe(3);
    expect(capped.riskIndicators).toEqual(['listing-truncated']);
    expect(
      summarizeTree([entry('a.py', 'a')], { truncated: true, maxFiles: 2 }).riskIndicators,
    ).toEqual(['listing-truncated']);
  });

  it('excludes boilerplate and measures blob overlap', () => {
    expect(isBoilerplate({ path: 'LICENSE', sha: sha('l') })).toBe(true);
    expect(isBoilerplate({ path: 'docs/.gitignore', sha: sha('g') })).toBe(true);
    expect(isBoilerplate({ path: 'empty.py', sha: EMPTY_BLOB_SHA })).toBe(true);
    expect(isBoilerplate({ path: 'exploit.py', sha: sha('e') })).toBe(false);
    expect(
      blobSimilarity(new Set(['a', 'b', 'c', 'd']), new Set(['a', 'b', 'c', 'e'])),
    ).toBeCloseTo(0.6, 3);
    expect(blobSimilarity(new Set(['a']), new Set(['a']))).toBe(0);
  });
});

describe('references', () => {
  it('parses GitHub repository URLs and refuses everything else', () => {
    expect(parseGithubRepositoryUrl('https://github.com/Owner/repo-name.git')).toMatchObject({
      fullName: 'Owner/repo-name',
      url: 'https://github.com/Owner/repo-name',
    });
    expect(parseGithubRepositoryUrl('https://github.com/owner/repo/blob/main/x.py')?.fullName).toBe(
      'owner/repo',
    );
    for (const url of [
      'https://github.com/advisories/GHSA-xxxx-xxxx-xxxx',
      'https://github.com/owner',
      'https://github.com.evil.test/owner/repo',
      'https://user:pw@github.com/owner/repo',
      'https://github.com/-bad/repo',
      'https://github.com/owner/..',
      'ftp://github.com/owner/repo',
    ]) {
      expect(parseGithubRepositoryUrl(url), url).toBeNull();
    }
  });

  it('classifies PoC hosts and exploit-tagged references', () => {
    expect(classifyReference('https://github.com/a/b', [])?.kind).toBe('github-repository');
    expect(classifyReference('https://gist.github.com/a/123', [])?.kind).toBe('github-gist');
    expect(classifyReference('https://www.exploit-db.com/exploits/51234', [])?.kind).toBe(
      'exploit-db',
    );
    expect(classifyReference('https://packetstormsecurity.com/files/170000/x.html', [])?.kind).toBe(
      'packet-storm',
    );
    expect(classifyReference('https://vendor.example/advisory', ['Exploit'])?.kind).toBe('other');
    expect(classifyReference('https://vendor.example/advisory', ['Patch'])).toBeNull();
    expect(classifyReference('https://www.exploit-db.com/about', [])).toBeNull();
  });
});

describe('GitHub repository mapping', () => {
  it('builds the canonical URL and sanitises owner-written text', () => {
    const mapped = mapGithubRepository(
      githubRepo({
        id: 1,
        name: `${CVE}-poc`,
        html_url: 'https://evil.example/phish',
        description: 'Exploit ‮fdp.exe',
        topics: ['cve', 'Bad Topic', 'poc'],
        language: 'Python',
      }),
    );
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.repository.url).toBe(`https://github.com/zz-test-owner/${CVE}-poc`);
    expect(mapped.repository.description).toBe('Exploit fdp.exe');
    expect(mapped.repository.topics).toEqual(['cve', 'poc']);
    expect(mapped.repository.owner).toMatchObject({ externalId: '9000001', type: 'user' });
  });

  it('refuses private, inconsistent and malformed repositories', () => {
    expect(mapGithubRepository(githubRepo({ id: 2, name: 'x', private: true }))).toMatchObject({
      ok: false,
      issue: 'private repository',
    });
    expect(
      mapGithubRepository(githubRepo({ id: 3, name: 'x', full_name: 'other/x' })),
    ).toMatchObject({ ok: false });
    expect(mapGithubRepository(githubRepo({ id: 4, name: '../etc' }))).toMatchObject({
      ok: false,
      issue: 'invalid repository name',
    });
    expect(
      mapGithubRepository(githubRepo({ id: 5, name: 'x', owner: 'bad_login!' })),
    ).toMatchObject({ ok: false });
    expect(mapGithubRepository({ id: 'nope' })).toMatchObject({ ok: false, externalId: null });
  });
});

describe('verification workflow', () => {
  const researcher: Permission[] = ['poc:read', 'poc:manage', 'quarantine:read'];
  const admin: Permission[] = [...researcher, 'quarantine:manage'];

  it('allows the documented transitions only', () => {
    expect(canTransitionVerification('unverified', 'verified')).toBe(true);
    expect(canTransitionVerification('rejected', 'verified')).toBe(false);
    expect(canTransitionVerification('malicious', 'verified')).toBe(false);
    expect(checkVerificationTransition('unverified', 'unverified', admin)).toEqual({
      ok: false,
      reason: 'same-status',
    });
    expect(checkVerificationTransition('rejected', 'verified', admin)).toEqual({
      ok: false,
      reason: 'not-allowed',
    });
  });

  it('requires quarantine:manage to leave malicious', () => {
    expect(checkVerificationTransition('verified', 'malicious', researcher)).toEqual({ ok: true });
    expect(checkVerificationTransition('malicious', 'in-review', researcher)).toEqual({
      ok: false,
      reason: 'forbidden',
    });
    expect(checkVerificationTransition('malicious', 'in-review', admin)).toEqual({ ok: true });
    expect(checkVerificationTransition('unverified', 'verified', ['poc:read'])).toEqual({
      ok: false,
      reason: 'forbidden',
    });
  });
});

describe('scan scheduling', () => {
  const day = 86_400_000;

  it('rescans exploited and recent CVEs more often', () => {
    expect(nextScanDelayMs({ inKev: true, epssScore: null, publishedAt: null }, NOW)).toBe(day);
    expect(nextScanDelayMs({ inKev: false, epssScore: 0.5, publishedAt: null }, NOW)).toBe(day);
    expect(
      nextScanDelayMs(
        { inKev: false, epssScore: 0.01, publishedAt: new Date(NOW.getTime() - 5 * day) },
        NOW,
      ),
    ).toBe(2 * day);
    expect(
      nextScanDelayMs(
        { inKev: false, epssScore: null, publishedAt: new Date(NOW.getTime() - 100 * day) },
        NOW,
      ),
    ).toBe(14 * day);
    expect(nextScanDelayMs({ inKev: false, epssScore: null, publishedAt: null }, NOW)).toBe(
      60 * day,
    );
  });

  it('orders CVE record events and schedules scans after changes', () => {
    const stored = { recordId: 'r1', recordVersion: 2, deletedAt: null, eventOccurredAt: NOW };
    expect(isNewer(stored, { recordId: 'r1', version: 2, deleted: false, occurredAt: NOW })).toBe(
      false,
    );
    expect(isNewer(stored, { recordId: 'r1', version: 3, deleted: false, occurredAt: NOW })).toBe(
      true,
    );
    expect(isNewer(stored, { recordId: 'r1', version: 2, deleted: true, occurredAt: NOW })).toBe(
      true,
    );
    expect(
      isNewer(stored, {
        recordId: 'r2',
        version: 1,
        deleted: false,
        occurredAt: new Date(NOW.getTime() + 1),
      }),
    ).toBe(true);

    const later = new Date(NOW.getTime() + day);
    expect(
      scheduleAfterChange(null, { state: 'published', inKev: false, deleted: false }, NOW),
    ).toEqual(NOW);
    expect(
      scheduleAfterChange(
        { inKev: false, nextScanAt: later },
        { state: 'published', inKev: false, deleted: false },
        NOW,
      ),
    ).toEqual(later);
    expect(
      scheduleAfterChange(
        { inKev: false, nextScanAt: later },
        { state: 'published', inKev: true, deleted: false },
        NOW,
      ),
    ).toEqual(NOW);
    expect(
      scheduleAfterChange(null, { state: 'rejected', inKev: false, deleted: false }, NOW),
    ).toBeNull();
  });
});
