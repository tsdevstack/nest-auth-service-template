import type { LoggerService, RedisService } from '@tsdevstack/nest-common';
import type { PrismaService } from '../prisma/prisma.service';
import type { ApiKeyIndexService } from './api-key-index.service';
import { ApiKeyUsageService } from './api-key-usage.service';

/**
 * Branches around the Redis reads; the copy itself runs against a real Redis
 * in api-keys.redis.spec.ts.
 */
describe('ApiKeyUsageService', () => {
  let index: { rebuildIfMissing: jest.Mock; isIndexPresent: jest.Mock };
  let prisma: { apiKey: { findMany: jest.Mock }; $executeRaw: jest.Mock };
  let service: ApiKeyUsageService;

  beforeEach(() => {
    index = {
      rebuildIfMissing: jest.fn().mockResolvedValue({
        status: 'present',
        recordsWritten: 0,
        countersSeeded: 0,
      }),
      isIndexPresent: jest.fn().mockResolvedValue(true),
    };
    prisma = {
      apiKey: { findMany: jest.fn().mockResolvedValue([]) },
      $executeRaw: jest.fn(),
    };
    const logger = { child: () => logger, info: jest.fn(), warn: jest.fn() };
    service = new ApiKeyUsageService(
      { getClient: jest.fn() } as unknown as RedisService,
      prisma as unknown as PrismaService,
      index as unknown as ApiKeyIndexService,
      logger as unknown as LoggerService,
    );
  });

  it('runs the rebuild check first', async () => {
    await service.sync();
    expect(index.rebuildIfMissing).toHaveBeenCalledWith('usage-job');
  });

  it('copies nothing while the index is missing', async () => {
    index.rebuildIfMissing.mockResolvedValue({
      status: 'locked',
      recordsWritten: 0,
      countersSeeded: 0,
    });
    index.isIndexPresent.mockResolvedValue(false);

    await expect(service.sync()).resolves.toEqual({
      success: false,
      rebuild: 'locked',
      keys: 0,
      periodsUpdated: 0,
      lastUsedUpdated: 0,
      skipped: 'index missing',
    });
    expect(prisma.apiKey.findMany).not.toHaveBeenCalled();
  });

  it('only syncs keys that were usable since the previous month started', async () => {
    await expect(service.sync()).resolves.toMatchObject({
      success: true,
      keys: 0,
    });
    const where = (
      prisma.apiKey.findMany.mock.calls[0] as [{ where: { AND: unknown[] } }]
    )[0].where;
    const cutoff = (
      where.AND[0] as { OR: [unknown, { revokedAt: { gte: Date } }] }
    ).OR[1].revokedAt.gte;
    const now = new Date();
    const previousMonthStart = Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth() - 1,
      1,
    );
    expect(cutoff.getTime()).toBe(previousMonthStart);
  });
});
