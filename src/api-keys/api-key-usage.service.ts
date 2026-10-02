import { Injectable } from '@nestjs/common';
import {
  API_KEY_WEEK_SECONDS,
  LoggerService,
  RedisService,
  buildApiKeyCounterKey,
  buildApiKeyLastUsedKey,
  getApiKeyWindowStart,
} from '@tsdevstack/nest-common';
import { PrismaService } from '../prisma/prisma.service';
import { ApiKeyIndexService } from './api-key-index.service';
import { API_KEY_BATCH_SIZE } from './api-keys.constants';
import type { ApiKeyUsageSyncResult } from './api-keys.types';
import { formatApiKeyUsagePeriod } from './utils/format-api-key-usage-period';

/**
 * Usage sync job (`POST /jobs/sync-api-key-usage`, every few minutes).
 *
 * Redis is not durable, so week and month totals are copied to
 * `ApiKeyUsage` (current and previous period, so the final total of a
 * finished period is kept), and the last-used times to `ApiKey.lastUsedAt`.
 * Stored totals (BIGINT) never go down (`GREATEST`). Before copying, the index is
 * rebuilt if its marker is missing; while the index is still missing
 * nothing is copied, so post-wipe counters never overwrite saved totals.
 */
@Injectable()
export class ApiKeyUsageService {
  private readonly logger: LoggerService;

  constructor(
    private readonly redis: RedisService,
    private readonly prisma: PrismaService,
    private readonly index: ApiKeyIndexService,
    logger: LoggerService,
  ) {
    this.logger = logger.child('ApiKeyUsageService');
  }

  async sync(): Promise<ApiKeyUsageSyncResult> {
    const rebuild = await this.index.rebuildIfMissing('usage-job');
    const result: ApiKeyUsageSyncResult = {
      success: true,
      rebuild: rebuild.status,
      keys: 0,
      periodsUpdated: 0,
      lastUsedUpdated: 0,
    };

    if (!(await this.index.isIndexPresent())) {
      this.logger.warn('API key index still missing; usage not synced');
      return { ...result, success: false, skipped: 'index missing' };
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const previousWeek = nowSeconds - API_KEY_WEEK_SECONDS;
    const previousMonth = getApiKeyWindowStart('month', nowSeconds) - 1;
    // Keys that stopped working before the previous month have nothing left to sync
    const cutoff = new Date(
      getApiKeyWindowStart('month', previousMonth) * 1000,
    );

    const counters = [
      { window: 'week' as const, at: nowSeconds },
      { window: 'week' as const, at: previousWeek },
      { window: 'month' as const, at: nowSeconds },
      { window: 'month' as const, at: previousMonth },
    ].map(({ window, at }) => ({
      window,
      at,
      period: formatApiKeyUsagePeriod(window, at),
    }));

    let afterId: string | null = null;
    for (;;) {
      const rows: { id: string; keyHash: string }[] =
        await this.prisma.apiKey.findMany({
          where: {
            AND: [
              { OR: [{ revokedAt: null }, { revokedAt: { gte: cutoff } }] },
              { OR: [{ expiresAt: null }, { expiresAt: { gte: cutoff } }] },
            ],
            ...(afterId !== null && { id: { gt: afterId } }),
          },
          select: { id: true, keyHash: true },
          orderBy: { id: 'asc' },
          take: API_KEY_BATCH_SIZE,
        });
      if (rows.length === 0) break;

      // One MGET per key: all of its names share one hash slot
      const pipeline = this.redis.getClient().pipeline();
      for (const row of rows) {
        pipeline.mget(
          ...counters.map(({ window, at }) =>
            buildApiKeyCounterKey(row.keyHash, window, at),
          ),
          buildApiKeyLastUsedKey(row.keyHash),
        );
      }
      const replies = (await pipeline.exec()) ?? [];

      for (const [index, row] of rows.entries()) {
        const [error, values] = replies[index] ?? [];
        if (error) throw error;
        const read = values as (string | null)[];

        for (const [position, { period }] of counters.entries()) {
          // Redis counters are 64-bit: parse exactly, store as BIGINT
          const count = BigInt(read[position] ?? 0);
          if (count > 0n) {
            await this.prisma.$executeRaw`
              INSERT INTO "ApiKeyUsage" ("keyId", "period", "count")
              VALUES (${row.id}, ${period}, ${count})
              ON CONFLICT ("keyId", "period")
              DO UPDATE SET "count" = GREATEST("ApiKeyUsage"."count", EXCLUDED."count")`;
            result.periodsUpdated += 1;
          }
        }

        const lastUsed = Number(read[counters.length] ?? 0);
        if (lastUsed > 0) {
          const lastUsedAt = new Date(lastUsed * 1000);
          // Raw update: keeps updatedAt for admin changes
          result.lastUsedUpdated += await this.prisma.$executeRaw`
            UPDATE "ApiKey" SET "lastUsedAt" = ${lastUsedAt}
            WHERE "id" = ${row.id}
              AND ("lastUsedAt" IS NULL OR "lastUsedAt" < ${lastUsedAt})`;
        }
      }

      result.keys += rows.length;
      afterId = rows[rows.length - 1].id;
    }

    this.logger.info('API key usage synced', { ...result });
    return result;
  }
}
