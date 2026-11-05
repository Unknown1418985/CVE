import type { ArtifactObjectStore } from '../storage/object-store.js';
import type { DownloadJobQueue } from '../download/download-jobs.js';
import type { SourcePolicy } from '../domain/sources.js';

export const DOWNLOAD_JOBS = Symbol('DOWNLOAD_JOBS');
export const SOURCE_POLICIES = Symbol('SOURCE_POLICIES');
export const OBJECT_STORE = Symbol('OBJECT_STORE');
export const DOWNLOAD_SETTINGS = Symbol('DOWNLOAD_SETTINGS');

export interface DownloadSettings {
  readonly maxAttempts: number;
}

export type { ArtifactObjectStore, DownloadJobQueue, SourcePolicy };
