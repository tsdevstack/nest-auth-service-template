import type { ApiKey, ApiKeyUsage } from '../generated/prisma/client';

/** A freshly generated key. `key` is returned to the admin once, never stored. */
export interface GeneratedApiKey {
  key: string;
  prefix: string;
  keyHash: string;
}

/** The database fields a Redis record is built from */
export type ApiKeyRecordSource = Pick<
  ApiKey,
  | 'id'
  | 'consumer'
  | 'status'
  | 'limitPerMinute'
  | 'limitPerHour'
  | 'limitPerDay'
  | 'limitPerWeek'
  | 'limitPerMonth'
  | 'expiresAt'
  | 'revokedAt'
>;

/** A key loaded for the rebuild, with its saved totals of the current periods */
export type ApiKeyRebuildRow = ApiKey & { usage: ApiKeyUsage[] };

/** What the record entry of a key should be: a value with its expiry, or absent */
export type ApiKeyRecordState = {
  value: string;
  /** Absolute expiry in epoch seconds; null for none */
  expireAt: number | null;
} | null;

/** A completed record write, with what it replaced (for an exact undo) */
export interface ApiKeyRecordWrite {
  key: string;
  /** Value the write left; null when it deleted the entry */
  written: string | null;
  /** Value before the write; null when there was none */
  previous: string | null;
  /** Absolute expiry of the previous value in ms; null for none */
  previousExpireAtMs: number | null;
}

/** Outcome of a rebuild attempt */
export interface ApiKeyRebuildResult {
  /**
   * `present`: the marker exists, nothing to do. `locked`: another instance
   * holds the lock. `rebuilt`: records written and the marker set.
   * `interrupted`: Redis reconnected or the lock was lost during the run
   * (for example a restart that emptied Redis), so the marker was not
   * written; a follow-up run or the next trigger rebuilds again.
   */
  status: 'present' | 'locked' | 'rebuilt' | 'interrupted';
  recordsWritten: number;
  countersSeeded: number;
}

/** Outcome of the usage sync job */
export interface ApiKeyUsageSyncResult {
  success: boolean;
  rebuild: ApiKeyRebuildResult['status'];
  keys: number;
  periodsUpdated: number;
  lastUsedUpdated: number;
  /** Set when nothing was synced */
  skipped?: string;
}
