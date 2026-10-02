import {
  Injectable,
  OnApplicationBootstrap,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import {
  API_KEY_INDEX_MARKER_KEY,
  API_KEY_REBUILD_LOCK_KEY,
  API_KEY_RECORD_VERSION,
  LoggerService,
  RedisService,
  buildApiKeyCounterKey,
  buildApiKeyRecordKey,
  decodeApiKeyRecord,
  getApiKeyCounterExpireAt,
} from '@tsdevstack/nest-common';
import type Redis from 'ioredis';
import { PrismaService } from '../prisma/prisma.service';
import { ApiKeyStatus } from '../generated/prisma/enums';
import {
  API_KEY_BATCH_SIZE,
  API_KEY_REBUILD_LOCK_TTL_MS,
  REBUILD_KEY_SCRIPT,
  RELEASE_LOCK_SCRIPT,
  REPAIR_RECORD_SCRIPT,
  UNDO_RECORD_SCRIPT,
  WRITE_RECORD_SCRIPT,
} from './api-keys.constants';
import type {
  ApiKeyRebuildResult,
  ApiKeyRebuildRow,
  ApiKeyRecordState,
  ApiKeyRecordWrite,
} from './api-keys.types';
import { buildApiKeySeedFlagKey } from './utils/build-api-key-seed-flag-key';
import { formatApiKeyUsagePeriod } from './utils/format-api-key-usage-period';
import { resolveApiKeyRecordState } from './utils/resolve-api-key-record-state';
import { runRedisScript } from './utils/run-redis-script';

/**
 * Keeps the Redis index Kong reads (`apikey:{<h>}:rec` records and the
 * `apikey:meta` marker) in step with Postgres.
 *
 * - Writes: every change writes the full record first; the caller writes
 *   Postgres next and calls {@link repairRecordWrite} if that fails or
 *   conflicts.
 * - Rebuild: only when the marker is missing (Redis lost its data). Under a
 *   lock, writes each active, unexpired key's record only where none exists
 *   (never undoing a newer change or reviving a revoked key), adds the saved
 *   week and month totals to the counters once, and writes the marker last.
 *   Runs at startup, whenever the Redis connection becomes ready, and from
 *   the usage sync job. The marker is skipped when Redis reconnected or the
 *   lock was lost during the run (a restart may have emptied Redis after
 *   some records were written); a trigger during a run schedules exactly one
 *   follow-up run.
 *
 * Every multi-key command touches only one key's hash-tagged names; the
 * marker and the lock are only used with single-key commands (cluster-safe).
 */
@Injectable()
export class ApiKeyIndexService
  implements OnModuleInit, OnApplicationBootstrap, OnModuleDestroy
{
  private readonly logger: LoggerService;
  private unsubscribeReady?: () => void;
  private rebuildInFlight: Promise<ApiKeyRebuildResult> | null = null;
  private followUpRequested = false;
  /** Incremented on every Redis `ready` event; a change means a reconnect */
  private readyGeneration = 0;

  constructor(
    private readonly redis: RedisService,
    private readonly prisma: PrismaService,
    logger: LoggerService,
  ) {
    this.logger = logger.child('ApiKeyIndexService');
  }

  onModuleInit(): void {
    this.unsubscribeReady = this.redis.onReady(() => {
      this.readyGeneration += 1;
      this.rebuildInBackground('redis-ready');
    });
  }

  onApplicationBootstrap(): void {
    // The first `ready` usually fires before this service subscribes
    if (this.redis.isReady()) {
      this.rebuildInBackground('startup');
    }
  }

  onModuleDestroy(): void {
    this.unsubscribeReady?.();
  }

  /**
   * Sets a key's record entry to `state` (null deletes it) and returns what
   * it replaced. Throws when Redis fails; nothing has changed then.
   */
  async writeRecord(
    keyHash: string,
    state: ApiKeyRecordState,
  ): Promise<ApiKeyRecordWrite> {
    const key = buildApiKeyRecordKey(keyHash);
    const reply = await runRedisScript(
      this.client(),
      WRITE_RECORD_SCRIPT,
      [key],
      [
        state?.value ?? '',
        state?.expireAt != null ? String(state.expireAt) : '',
      ],
    );

    const [previous, previousAt] = Array.isArray(reply)
      ? (reply as [string?, number?])
      : [];

    return {
      key,
      written: state?.value ?? null,
      previous: previous ?? null,
      previousExpireAtMs:
        typeof previousAt === 'number' && previousAt > 0 ? previousAt : null,
    };
  }

  /**
   * Repairs a record after the Postgres write that followed it failed or
   * conflicted: re-reads the database and sets the record to the state
   * resolved from it, only while the record still holds what our write left
   * (compare-and-set; a newer write by someone else wins). This covers an
   * ambiguous failure too (Postgres committed but reported an error): the
   * re-read sees the commit. It also never deletes a record a rebuild could
   * not write because ours was there.
   *
   * When the re-read itself fails, falls back to {@link undoRecordWrite}
   * (restore the previous Redis state), except for a revoked record, which
   * is left in place: failing towards "revoked" is the safe direction.
   *
   * Never throws.
   *
   * @param loadTruth - Reads the row now and resolves its record state
   * @returns true when Redis now matches the database (or was left revoked)
   */
  async repairRecordWrite(
    write: ApiKeyRecordWrite,
    loadTruth: () => Promise<ApiKeyRecordState>,
  ): Promise<boolean> {
    let truth: ApiKeyRecordState;
    try {
      truth = await loadTruth();
    } catch (error) {
      this.logger.error(
        'Could not re-read an API key after a failed write; falling back to the undo',
        error,
      );
      if (this.isRevokedRecord(write.written)) {
        this.logger.warn(
          'Leaving the revoked API key record in place (safe direction)',
        );
        return true;
      }
      return await this.undoRecordWrite(write);
    }

    try {
      const repaired = await runRedisScript(
        this.client(),
        REPAIR_RECORD_SCRIPT,
        [write.key],
        [
          write.written ?? '',
          truth?.value ?? '',
          truth?.expireAt != null ? String(truth.expireAt) : '',
        ],
      );
      if (repaired !== 1) {
        this.logger.warn(
          'API key record changed again before the repair; the newer value stays',
        );
      }
      return true;
    } catch (error) {
      this.logger.error(
        'Repair of an API key record failed; Redis and Postgres differ until the operation is repeated',
        error,
      );
      return false;
    }
  }

  /**
   * Restores what a write replaced, unless the entry changed again since
   * (then the newer value stays). Fallback of {@link repairRecordWrite} when
   * the database cannot be read. Never throws: a failed undo is logged and
   * left as drift until the admin repeats the operation.
   *
   * @returns true when the previous state was restored
   */
  async undoRecordWrite(write: ApiKeyRecordWrite): Promise<boolean> {
    try {
      const restored = await runRedisScript(
        this.client(),
        UNDO_RECORD_SCRIPT,
        [write.key],
        [
          write.written ?? '',
          write.previous ?? '',
          write.previousExpireAtMs !== null
            ? String(write.previousExpireAtMs)
            : '',
        ],
      );
      if (restored !== 1) {
        this.logger.warn(
          'API key record changed again before the undo; the newer value stays',
        );
      }
      return restored === 1;
    } catch (error) {
      this.logger.error(
        'Undo of an API key record write failed; Redis and Postgres differ until the operation is repeated',
        error,
      );
      return false;
    }
  }

  /** Whether the index marker exists (false means Redis lost the index) */
  async isIndexPresent(): Promise<boolean> {
    return (await this.client().exists(API_KEY_INDEX_MARKER_KEY)) === 1;
  }

  /**
   * Rebuilds the index when the marker is missing; other instances are kept
   * out by the lock. A call while a run is in flight schedules exactly one
   * follow-up run (several calls share it) and gets the result of the last
   * run: the in-flight run may have started before whatever caused the call
   * (for example Redis restarting empty).
   */
  rebuildIfMissing(trigger: string): Promise<ApiKeyRebuildResult> {
    if (this.rebuildInFlight) {
      this.followUpRequested = true;
      return this.rebuildInFlight;
    }
    this.rebuildInFlight = this.runRebuilds(trigger).finally(() => {
      this.rebuildInFlight = null;
    });
    return this.rebuildInFlight;
  }

  /**
   * Loads one batch of keys to restore: active, not expired, with their
   * saved totals of the current week and month.
   */
  async loadRebuildBatch(
    afterId: string | null,
    nowSeconds: number,
  ): Promise<ApiKeyRebuildRow[]> {
    const periods = [
      formatApiKeyUsagePeriod('week', nowSeconds),
      formatApiKeyUsagePeriod('month', nowSeconds),
    ];

    return await this.prisma.apiKey.findMany({
      where: {
        status: ApiKeyStatus.ACTIVE,
        OR: [
          { expiresAt: null },
          { expiresAt: { gt: new Date(nowSeconds * 1000) } },
        ],
        ...(afterId !== null && { id: { gt: afterId } }),
      },
      include: { usage: { where: { period: { in: periods } } } },
      orderBy: { id: 'asc' },
      take: API_KEY_BATCH_SIZE,
    });
  }

  /**
   * Writes the batch: each record only if missing, saved totals added once.
   *
   * @returns records written and counters seeded
   */
  async writeRebuildBatch(
    rows: ApiKeyRebuildRow[],
    nowSeconds: number,
  ): Promise<{ recordsWritten: number; countersSeeded: number }> {
    const weekPeriod = formatApiKeyUsagePeriod('week', nowSeconds);
    const monthPeriod = formatApiKeyUsagePeriod('month', nowSeconds);
    const weekExpireAt = String(getApiKeyCounterExpireAt('week', nowSeconds));
    const monthExpireAt = String(getApiKeyCounterExpireAt('month', nowSeconds));

    let recordsWritten = 0;
    let countersSeeded = 0;

    for (const row of rows) {
      const state = resolveApiKeyRecordState(row, nowSeconds);
      if (state === null) continue;

      const savedTotal = (period: string): string =>
        String(row.usage.find((usage) => usage.period === period)?.count ?? 0);

      const reply = await runRedisScript(
        this.client(),
        REBUILD_KEY_SCRIPT,
        [
          buildApiKeyRecordKey(row.keyHash),
          buildApiKeyCounterKey(row.keyHash, 'week', nowSeconds),
          buildApiKeySeedFlagKey(row.keyHash, 'week', nowSeconds),
          buildApiKeyCounterKey(row.keyHash, 'month', nowSeconds),
          buildApiKeySeedFlagKey(row.keyHash, 'month', nowSeconds),
        ],
        [
          state.value,
          state.expireAt !== null ? String(state.expireAt) : '',
          savedTotal(weekPeriod),
          weekExpireAt,
          savedTotal(monthPeriod),
          monthExpireAt,
        ],
      );

      const [written, seeded] = reply as [number, number];
      recordsWritten += written;
      countersSeeded += seeded;
    }

    return { recordsWritten, countersSeeded };
  }

  /** Writes the marker; the index counts as complete from here on */
  async writeMarker(nowSeconds: number): Promise<void> {
    await this.client().set(
      API_KEY_INDEX_MARKER_KEY,
      JSON.stringify({ v: API_KEY_RECORD_VERSION, rebuiltAt: nowSeconds }),
    );
  }

  /** Whether the rebuild lock still holds this run's token */
  async holdsRebuildLock(token: string): Promise<boolean> {
    return (await this.client().get(API_KEY_REBUILD_LOCK_KEY)) === token;
  }

  private async runRebuilds(trigger: string): Promise<ApiKeyRebuildResult> {
    for (;;) {
      this.followUpRequested = false;
      let result: ApiKeyRebuildResult;
      try {
        result = await this.runRebuild(trigger);
      } catch (error) {
        if (!this.followUpRequested) throw error;
        this.logger.warn(
          'API key index rebuild failed; running the follow-up',
          {
            trigger,
            error: error instanceof Error ? error.message : String(error),
          },
        );
        continue;
      }
      if (!this.followUpRequested) return result;
      trigger = 'follow-up';
    }
  }

  private async runRebuild(trigger: string): Promise<ApiKeyRebuildResult> {
    const nothing = { recordsWritten: 0, countersSeeded: 0 };

    if (await this.isIndexPresent()) {
      return { status: 'present', ...nothing };
    }

    const client = this.client();
    const generation = this.readyGeneration;
    const token = randomUUID();
    const locked = await client.set(
      API_KEY_REBUILD_LOCK_KEY,
      token,
      'PX',
      API_KEY_REBUILD_LOCK_TTL_MS,
      'NX',
    );
    if (locked !== 'OK') {
      this.logger.info('API key index rebuild already running elsewhere', {
        trigger,
      });
      return { status: 'locked', ...nothing };
    }

    try {
      // Another instance may have finished between the check and the lock
      if (await this.isIndexPresent()) {
        return { status: 'present', ...nothing };
      }

      this.logger.warn('API key index marker missing; rebuilding', { trigger });
      const nowSeconds = Math.floor(Date.now() / 1000);
      let recordsWritten = 0;
      let countersSeeded = 0;
      let afterId: string | null = null;

      for (;;) {
        const rows = await this.loadRebuildBatch(afterId, nowSeconds);
        if (rows.length === 0) break;

        const batch = await this.writeRebuildBatch(rows, nowSeconds);
        recordsWritten += batch.recordsWritten;
        countersSeeded += batch.countersSeeded;
        afterId = rows[rows.length - 1].id;
      }

      // A reconnect or a lost lock means Redis may have restarted empty
      // after some records were written: a marker now would turn the
      // missing records into 401 instead of 503
      if (
        this.readyGeneration !== generation ||
        !(await this.holdsRebuildLock(token))
      ) {
        this.logger.warn(
          'Redis reconnected or the rebuild lock was lost during the API key rebuild; marker not written',
          { trigger },
        );
        return { status: 'interrupted', recordsWritten, countersSeeded };
      }

      await this.writeMarker(nowSeconds);
      this.logger.info('API key index rebuilt', {
        trigger,
        recordsWritten,
        countersSeeded,
      });
      return { status: 'rebuilt', recordsWritten, countersSeeded };
    } finally {
      await runRedisScript(
        client,
        RELEASE_LOCK_SCRIPT,
        [API_KEY_REBUILD_LOCK_KEY],
        [token],
      ).catch((error: unknown) => {
        this.logger.warn('Could not release the API key rebuild lock', {
          error: error instanceof Error ? error.message : String(error),
        });
      });
    }
  }

  private isRevokedRecord(value: string | null): boolean {
    if (value === null) return false;
    try {
      return decodeApiKeyRecord(value).status === 'revoked';
    } catch {
      return false;
    }
  }

  private rebuildInBackground(trigger: string): void {
    this.rebuildIfMissing(trigger).catch((error: unknown) => {
      this.logger.error('API key index rebuild failed', error, { trigger });
    });
  }

  private client(): Redis {
    return this.redis.getClient();
  }
}
