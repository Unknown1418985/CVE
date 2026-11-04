import type {
  AuditActorType,
  AuditEvent,
  AuditOutcome,
  DomainEventEnvelope,
  ListAuditEventsQuery,
} from '@cve/contracts';

export interface NewAuditEntry {
  readonly occurredAt: Date;
  readonly source: string;
  readonly sourceEventId?: string;
  readonly action: string;
  readonly outcome: AuditOutcome;
  readonly actorType: AuditActorType;
  readonly actorId?: string | undefined;
  readonly actorUsername?: string | undefined;
  readonly resourceType?: string | undefined;
  readonly resourceId?: string | undefined;
  readonly ipAddress?: string | undefined;
  readonly userAgent?: string | undefined;
  readonly correlationId?: string | undefined;
  readonly details?: Readonly<Record<string, unknown>> | undefined;
}

export interface AuditRepository {
  /** Appends one entry and, atomically with it, the domain events it caused (outbox). */
  append(entry: NewAuditEntry, events?: readonly DomainEventEnvelope[]): Promise<void>;
  /** Appends entries, skipping ones already ingested (same `source` + `sourceEventId`). */
  appendMany(entries: readonly NewAuditEntry[]): Promise<number>;
  list(query: ListAuditEventsQuery): Promise<{ items: AuditEvent[]; total: number }>;
  find(id: string): Promise<AuditEvent | null>;
}

export interface StoredProfile {
  readonly keycloakUserId: string;
  readonly username: string;
  readonly email: string | null;
  readonly displayName: string | null;
  readonly jobTitle: string | null;
  readonly timezone: string;
  readonly firstSeenAt: Date;
  readonly lastSeenAt: Date;
}

export interface ProfilePatch {
  readonly displayName?: string | null;
  readonly jobTitle?: string | null;
  readonly timezone?: string;
}

export interface ProfileRepository {
  /** Creates the profile on first sight and refreshes username, email and `lastSeenAt`. */
  touch(
    user: { id: string; username: string; email: string | null },
    at: Date,
  ): Promise<StoredProfile>;
  update(userId: string, patch: ProfilePatch): Promise<StoredProfile>;
}

export interface SyncCursorRepository {
  get(name: string): Promise<Date | null>;
  set(name: string, position: Date): Promise<void>;
}

export const AUDIT_REPOSITORY = Symbol('AUDIT_REPOSITORY');
export const PROFILE_REPOSITORY = Symbol('PROFILE_REPOSITORY');
export const SYNC_CURSOR_REPOSITORY = Symbol('SYNC_CURSOR_REPOSITORY');
