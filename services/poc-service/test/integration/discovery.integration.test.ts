import 'reflect-metadata';

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { POC_EVENT_TYPES } from '@cve/contracts';

import { REFERENCE_CONSUMER, ReferenceCollector } from '../../src/events/reference-collector.js';
import { CveTracker } from '../../src/events/cve-tracker.js';
import { runDiscoverySweep, runMaintenance } from '../../src/discovery/discovery-jobs.js';
import type { DiscoveryEngine } from '../../src/discovery/discovery-engine.js';
import { createPrismaClient, type PrismaClient } from '../../src/persistence/prisma.js';
import { scoringSettings } from '../../src/runtime.js';
import { MockSource } from '../mock-source.js';
import { FakeJobQueue, sha, silentLogger } from '../support.js';
import {
  createEngine,
  cveRecordEvent,
  discoveryRequest,
  FakeGithub,
  integrationEnv,
  migrate,
  observationEvent,
  outboxTypes,
  pocDatabaseUrl,
  resetDatabase,
  syntheticCveId,
  TEST_OWNER,
} from './support.js';

// Everything here is synthetic test data (see support.ts), not real repositories or CVEs.

let prisma: PrismaClient;
let mock: MockSource;
let github: FakeGithub;
let jobs: FakeJobQueue;
let engine: DiscoveryEngine;

const signal = () => new AbortController().signal;
const file = (path: string, seed = path) => ({ path, sha: sha(seed) });

beforeAll(async () => {
  const url = pocDatabaseUrl();
  migrate(url);
  prisma = createPrismaClient(url);
  await resetDatabase(prisma);
});

afterAll(async () => {
  await resetDatabase(prisma);
  await prisma.$disconnect();
});

beforeEach(async () => {
  await resetDatabase(prisma);
  mock = await new MockSource().start();
  github = new FakeGithub(mock);
  jobs = new FakeJobQueue();
  engine = createEngine(prisma, integrationEnv(mock.origin), jobs);
});

afterEach(async () => {
  await mock.stop();
});

async function inspectAll(): Promise<void> {
  for (const { repositoryId } of jobs.inspections.splice(0)) {
    const outcome = await engine.run(
      discoveryRequest({ mode: 'repository', repositoryId }),
      signal(),
    );
    expect(outcome.status).toBe('succeeded');
  }
}

describe('CVE discovery', () => {
  it('stores repository metadata, owner, commit and file listing and scores the association', async () => {
    const cveId = syntheticCveId(101);
    github.add({
      id: 101,
      name: `${cveId}-poc`,
      description: `Proof of concept for ${cveId}`,
      topics: [cveId.toLowerCase()],
      commit: {
        sha: sha('c101'),
        treeSha: sha('t101'),
        files: [file('exploit.py'), file('README.md'), file('LICENSE', 'mit')],
      },
    });

    const outcome = await engine.run(discoveryRequest({ mode: 'cve', cveId }), signal());
    expect(outcome).toMatchObject({ status: 'succeeded' });
    if (outcome.status !== 'succeeded') return;
    expect(outcome.stats).toMatchObject({
      candidates: 1,
      repositoriesCreated: 1,
      associationsCreated: 1,
      inspectionsQueued: 1,
    });

    const repo = await prisma.pocRepository.findFirstOrThrow({ include: { owner: true } });
    expect(repo).toMatchObject({
      externalId: '101',
      fullName: `${TEST_OWNER}/${cveId}-poc`,
      url: `https://github.com/${TEST_OWNER}/${cveId}-poc`,
      latestCommitSha: null,
    });
    expect(repo.owner).toMatchObject({
      login: TEST_OWNER,
      externalId: '9000101',
      source: 'github',
    });
    expect(repo.firstDiscoveredAt).toBeInstanceOf(Date);

    await inspectAll();

    const inspected = await prisma.pocRepository.findUniqueOrThrow({ where: { id: repo.id } });
    expect(inspected.latestCommitSha).toBe(sha('c101'));
    expect(inspected.lastInspectedAt).toBeInstanceOf(Date);
    const commits = await prisma.repositoryCommit.findMany({ where: { repositoryId: repo.id } });
    expect(commits.map((commit) => commit.sha)).toEqual([sha('c101')]);
    const artifact = await prisma.pocArtifact.findFirstOrThrow({
      where: { repositoryId: repo.id },
      include: { files: true },
    });
    expect(artifact).toMatchObject({
      treeSha: sha('t101'),
      verificationStatus: 'unverified',
      duplicateKind: null,
      hasSourceCode: true,
      fileCount: 3,
    });
    expect(artifact.files.map((entry) => entry.path).sort()).toEqual([
      'LICENSE',
      'README.md',
      'exploit.py',
    ]);

    const association = await prisma.pocAssociation.findFirstOrThrow({ where: { cveId } });
    expect(Number(association.confidence)).toBeGreaterThanOrEqual(0.7);
    expect(association.confidenceLevel).toBe('high');
    expect(association.reviewStatus).toBe('candidate');
    expect(association.origin).toBe('discovered');
    const signals = association.signals as { kind: string }[];
    expect(signals.map((signal) => signal.kind)).toEqual(
      expect.arrayContaining(['name', 'description', 'topic']),
    );

    const types = await outboxTypes(prisma);
    expect(types).toEqual(
      expect.arrayContaining([
        POC_EVENT_TYPES.repositoryDiscovered,
        POC_EVENT_TYPES.associationDiscovered,
        POC_EVENT_TYPES.artifactDiscovered,
        POC_EVENT_TYPES.repositoryUpdated,
        POC_EVENT_TYPES.discoveryRunCompleted,
      ]),
    );

    // The tree is fetched once; a second inspection of the same commit does not fetch it again.
    jobs.inspections.push({ repositoryId: repo.id, dedupeKey: 'again' });
    await inspectAll();
    expect(mock.requestsTo(`/repos/${repo.fullName}/git/trees/${sha('t101')}`)).toHaveLength(1);
    expect(await prisma.pocArtifact.count()).toBe(1);
  });

  it('does not associate a CVE that only the search engine matched (README text is never trusted)', async () => {
    const cveId = syntheticCveId(102);
    github.add({
      id: 102,
      name: 'scanner-collection',
      readme: `mentions ${cveId}`,
      commit: 'empty',
    });
    const outcome = await engine.run(discoveryRequest({ mode: 'cve', cveId }), signal());
    expect(outcome).toMatchObject({ status: 'succeeded', stats: { associationsCreated: 0 } });
    expect(await prisma.pocAssociation.count()).toBe(0);
    // The repository is still recorded as a candidate.
    expect(await prisma.pocRepository.count()).toBe(1);
  });

  it('penalises forks, empty repositories and repositories mentioning many CVEs', async () => {
    const target = syntheticCveId(103);
    const many = Array.from({ length: 12 }, (_, index) => syntheticCveId(200 + index));
    github.add({
      id: 1031,
      name: `${target}-exploit`,
      commit: { sha: sha('a'), treeSha: sha('ta'), files: [file('poc.py')] },
    });
    github.add({ id: 1032, name: `${target}-exploit`, owner: 'zz-test-forker', fork: true });
    github.add({ id: 1033, name: `${target}-placeholder`, commit: 'empty' });
    github.add({
      id: 1034,
      name: 'cve-list',
      description: `${target} ${many.join(' ')}`,
      commit: { sha: sha('b'), treeSha: sha('tb'), files: [file('main.py')] },
    });
    await engine.run(discoveryRequest({ mode: 'cve', cveId: target }), signal());
    await inspectAll();

    const rows = await prisma.pocAssociation.findMany({
      where: { cveId: target },
      include: { repository: true },
    });
    const byId = new Map(rows.map((row) => [row.repository.externalId, row]));
    const confidence = (id: string) => Number(byId.get(id)?.confidence ?? 0);
    const penalties = (id: string) =>
      ((byId.get(id)?.penalties ?? []) as { kind: string }[]).map((penalty) => penalty.kind);

    expect(confidence('1031')).toBeGreaterThan(confidence('1032'));
    expect(penalties('1032')).toContain('fork');
    expect(penalties('1033')).toContain('empty-repository');
    expect(confidence('1031')).toBeGreaterThan(confidence('1033'));
    // The list repository mentions 13 CVEs in its description only.
    expect(byId.get('1034') === undefined || penalties('1034').includes('many-cves')).toBe(true);
    expect(confidence('1034')).toBeLessThan(0.4);
  });

  it('detects exact and near duplicates across repositories', async () => {
    const cveId = syntheticCveId(104);
    const shared = Array.from({ length: 9 }, (_, index) => file(`src/part${String(index)}.py`));
    github.add({
      id: 1041,
      name: `${cveId}-original`,
      commit: { sha: sha('o1'), treeSha: sha('to'), files: [...shared, file('extra-a.py')] },
    });
    await engine.run(discoveryRequest({ mode: 'cve', cveId }), signal());
    await inspectAll();

    github.add({
      id: 1042,
      name: `${cveId}-copy`,
      owner: 'zz-test-copier',
      // Same tree: byte-identical content.
      commit: { sha: sha('o2'), treeSha: sha('to'), files: [...shared, file('extra-a.py')] },
    });
    github.add({
      id: 1043,
      name: `${cveId}-variant`,
      owner: 'zz-test-variant',
      // 9 of 11 distinct significant blobs shared (Jaccard 0.82), plus boilerplate.
      commit: {
        sha: sha('o3'),
        treeSha: sha('tv'),
        files: [...shared, file('extra-b.py'), file('LICENSE', 'mit'), file('.gitignore', 'gi')],
      },
    });
    await engine.run(discoveryRequest({ mode: 'cve', cveId }), signal());
    await inspectAll();

    const artifacts = await prisma.pocArtifact.findMany({ include: { repository: true } });
    const byRepo = new Map(artifacts.map((artifact) => [artifact.repository.externalId, artifact]));
    const original = byRepo.get('1041');
    expect(original?.duplicateKind).toBeNull();
    expect(byRepo.get('1042')).toMatchObject({
      duplicateKind: 'exact',
      duplicateOfId: original?.id,
    });
    expect(Number(byRepo.get('1042')?.similarity)).toBe(1);
    expect(byRepo.get('1043')).toMatchObject({
      duplicateKind: 'near',
      duplicateOfId: original?.id,
    });
    expect(Number(byRepo.get('1043')?.similarity)).toBeGreaterThanOrEqual(0.8);
    expect(Number(byRepo.get('1043')?.similarity)).toBeLessThan(1);
  });

  it('marks a repository that disappeared as unavailable', async () => {
    const cveId = syntheticCveId(105);
    github.add({
      id: 105,
      name: `${cveId}-poc`,
      commit: { sha: sha('g'), treeSha: sha('tg'), files: [file('a.py')] },
    });
    await engine.run(discoveryRequest({ mode: 'cve', cveId }), signal());
    await inspectAll();
    const repo = await prisma.pocRepository.findFirstOrThrow();

    github.update(105, { gone: 451 });
    const outcome = await engine.run(
      discoveryRequest({ mode: 'repository', repositoryId: repo.id }),
      signal(),
    );
    expect(outcome.status).toBe('succeeded');
    const after = await prisma.pocRepository.findUniqueOrThrow({ where: { id: repo.id } });
    expect(after.status).toBe('unavailable');
    // History is kept.
    expect(await prisma.pocArtifact.count({ where: { repositoryId: repo.id } })).toBe(1);
  });

  it('records a new artifact version when the head commit changes', async () => {
    const cveId = syntheticCveId(106);
    github.add({
      id: 106,
      name: `${cveId}-poc`,
      commit: { sha: sha('v1'), treeSha: sha('tv1'), files: [file('a.py')] },
    });
    await engine.run(discoveryRequest({ mode: 'cve', cveId }), signal());
    await inspectAll();
    const repo = await prisma.pocRepository.findFirstOrThrow();

    github.update(106, {
      commit: { sha: sha('v2'), treeSha: sha('tv2'), files: [file('a.py'), file('b.py')] },
    });
    await engine.run(discoveryRequest({ mode: 'repository', repositoryId: repo.id }), signal());
    const artifacts = await prisma.pocArtifact.findMany({
      where: { repositoryId: repo.id },
      orderBy: { discoveredAt: 'asc' },
    });
    expect(artifacts.map((artifact) => artifact.commitSha)).toEqual([sha('v1'), sha('v2')]);
    const after = await prisma.pocRepository.findUniqueOrThrow({ where: { id: repo.id } });
    expect(after.latestArtifactId).toBe(artifacts[1]?.id);
    expect(await prisma.repositoryCommit.count({ where: { repositoryId: repo.id } })).toBe(2);
  });

  it('fails the run as retryable on a server error and records it', async () => {
    mock.route('/search/repositories', () => ({ status: 503 }));
    const outcome = await engine.run(
      discoveryRequest({ mode: 'cve', cveId: syntheticCveId(107), maxAttempts: 3 }),
      signal(),
    );
    expect(outcome).toMatchObject({ status: 'failed', retryable: true });
    const run = await prisma.discoveryRun.findFirstOrThrow();
    expect(run.status).toBe('failed');
    expect(await outboxTypes(prisma)).toContain(POC_EVENT_TYPES.discoveryRunFailed);
  });
});

describe('recent sweep', () => {
  it('keeps a pushed-at cursor in connector_states', async () => {
    const env = integrationEnv(mock.origin, {
      POC_GITHUB_RECENT_INITIAL_LOOKBACK_HOURS: '2',
      POC_GITHUB_RECENT_WINDOW_MINUTES: '60',
    });
    engine = createEngine(prisma, env, jobs);
    github.add({ id: 108, name: `${syntheticCveId(108)}-poc`, commit: 'empty' });
    const outcome = await engine.run(discoveryRequest({ mode: 'recent' }), signal());
    expect(outcome.status).toBe('succeeded');
    const state = await prisma.connectorState.findUniqueOrThrow({ where: { connector: 'github' } });
    const cursor = state.cursor as { pushedSince: string };
    expect(Date.parse(cursor.pushedSince)).toBeGreaterThan(Date.now() - 2 * 3_600_000);
    expect(mock.requestsTo('/search/repositories').length).toBeGreaterThanOrEqual(1);
    expect(await prisma.pocAssociation.count({ where: { cveId: syntheticCveId(108) } })).toBe(1);
  });
});

describe('CVE reference collector', () => {
  it('records PoC references, links known repositories, rescores them and marks removed ones', async () => {
    const cveId = syntheticCveId(110);
    github.add({
      id: 110,
      name: 'research-notes',
      commit: { sha: sha('r'), treeSha: sha('tr'), files: [file('x.py')] },
    });
    // Known repository without any CVE mention: the reference is the only evidence.
    await engine.run(
      discoveryRequest({ mode: 'repository', fullName: `${TEST_OWNER}/research-notes` }),
      signal(),
    );
    const repo = await prisma.pocRepository.findFirstOrThrow();
    const collector = new ReferenceCollector(
      prisma,
      jobs,
      scoringSettings(integrationEnv(mock.origin)),
      silentLogger,
    );

    const first = observationEvent({
      cveId,
      revision: 1,
      references: [
        { url: `https://github.com/${TEST_OWNER}/research-notes`, tags: ['Exploit'] },
        { url: `https://github.com/${TEST_OWNER}/unknown-repo` },
        { url: 'https://www.exploit-db.com/exploits/99999' },
        { url: 'https://vendor.example/advisory' },
      ],
    });
    await expect(collector.apply(first)).resolves.toMatchObject({ kind: 'applied', created: 3 });
    await expect(collector.apply(first)).resolves.toEqual({ kind: 'duplicate' });

    const references = await prisma.pocReference.findMany({ where: { cveId } });
    expect(references.map((reference) => reference.kind).sort()).toEqual([
      'exploit_db',
      'github_repository',
      'github_repository',
    ]);
    expect(references.find((reference) => reference.repositoryId === repo.id)).toBeDefined();
    const association = await prisma.pocAssociation.findUniqueOrThrow({
      where: { repositoryId_cveId: { repositoryId: repo.id, cveId } },
    });
    expect((association.signals as { kind: string }[]).map((signal) => signal.kind)).toContain(
      'cve-exploit-reference',
    );
    // The unknown repository is looked up by a job.
    expect(jobs.discovery.map((job) => job.payload)).toEqual([
      expect.objectContaining({
        mode: 'repository',
        fullName: `${TEST_OWNER.toLowerCase()}/unknown-repo`,
      }),
    ]);

    // An older revision is ignored; a newer one without the reference marks it removed.
    await expect(
      collector.apply(observationEvent({ cveId, revision: 1, references: [] })),
    ).resolves.toEqual({ kind: 'stale' });
    await collector.apply(observationEvent({ cveId, revision: 2, references: [] }));
    expect(await prisma.pocReference.count({ where: { cveId, removedAt: null } })).toBe(0);
    const rescored = await prisma.pocAssociation.findUnique({
      where: { repositoryId_cveId: { repositoryId: repo.id, cveId } },
    });
    expect(rescored === null || rescored.reviewStatus === 'candidate').toBe(true);
    expect(Number(rescored?.confidence ?? 0)).toBeLessThan(Number(association.confidence));
    expect(await prisma.processedEvent.count({ where: { consumer: REFERENCE_CONSUMER } })).toBe(3);
    expect(await outboxTypes(prisma)).toContain(POC_EVENT_TYPES.referenceDiscovered);
  });
});

describe('CVE tracker and the discovery sweep', () => {
  it('queues due published CVEs once, KEV first, and skips deleted ones', async () => {
    const tracker = new CveTracker(prisma, silentLogger);
    const kev = syntheticCveId(120);
    const plain = syntheticCveId(121);
    const rejected = syntheticCveId(122);
    await tracker.apply(cveRecordEvent(plain, { version: 1, recordId: crypto.randomUUID() }));
    await tracker.apply(
      cveRecordEvent(kev, { version: 1, recordId: crypto.randomUUID(), inKev: true }),
    );
    await tracker.apply(
      cveRecordEvent(rejected, { version: 1, recordId: crypto.randomUUID(), state: 'rejected' }),
    );
    const event = cveRecordEvent(syntheticCveId(123), {
      version: 1,
      recordId: crypto.randomUUID(),
    });
    await expect(tracker.apply(event)).resolves.toBe('applied');
    await expect(tracker.apply(event)).resolves.toBe('duplicate');

    const queued = await runDiscoverySweep({
      prisma,
      queue: jobs,
      batchSize: 2,
      logger: silentLogger,
    });
    expect(queued).toBe(2);
    expect(jobs.discovery[0]?.payload).toMatchObject({
      mode: 'cve',
      cveId: kev,
      trigger: 'scheduled',
    });
    // Leased: a second sweep picks only the remaining due CVE.
    await runDiscoverySweep({ prisma, queue: jobs, batchSize: 10, logger: silentLogger });
    const cves = jobs.discovery.map((job) => job.payload.cveId);
    expect(new Set(cves).size).toBe(cves.length);
    expect(cves).not.toContain(rejected);
    expect(cves).toHaveLength(3);

    // A successful scan schedules the next one.
    github.add({ id: 120, name: `${kev}-poc`, commit: 'empty' });
    await engine.run(discoveryRequest({ mode: 'cve', cveId: kev }), signal());
    const tracked = await prisma.trackedCve.findUniqueOrThrow({ where: { cveId: kev } });
    expect(tracked.scanCount).toBe(1);
    expect(tracked.nextScanAt?.getTime()).toBeGreaterThan(Date.now());
  });

  it('maintenance fails stale runs and re-queues lost inspections', async () => {
    const cveId = syntheticCveId(130);
    github.add({ id: 130, name: `${cveId}-poc`, commit: 'empty' });
    await engine.run(discoveryRequest({ mode: 'cve', cveId }), signal());
    jobs.inspections.splice(0);
    const repo = await prisma.pocRepository.findFirstOrThrow();
    await prisma.pocRepository.update({
      where: { id: repo.id },
      data: { inspectionDueAt: new Date(Date.now() - 3_600_000) },
    });
    await prisma.discoveryRun.create({
      data: {
        connector: 'github',
        mode: 'cve',
        trigger: 'manual',
        attempt: 1,
        startedAt: new Date(Date.now() - 86_400_000),
        stats: {},
      },
    });
    const result = await runMaintenance({
      prisma,
      queue: jobs,
      logger: silentLogger,
      githubEnabled: true,
      staleRunAfterMs: 3_600_000,
      processedEventRetentionDays: 7,
      outboxRetentionDays: 7,
      runRetentionDays: 90,
    });
    expect(result).toMatchObject({ staleRuns: 1, inspections: 1 });
    expect(jobs.inspections.map((job) => job.repositoryId)).toEqual([repo.id]);
  });
});
