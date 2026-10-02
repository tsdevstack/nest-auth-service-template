/**
 * API key writes against a real Postgres 17 (Docker): the conditional
 * `updateMany` inside interactive transactions (lost races are 409 and
 * roll back), `@updatedAt`, and the BIGINT usage totals with the job's
 * GREATEST upsert. Redis is replaced by stubs here; Redis behavior runs in
 * api-keys.redis.spec.ts.
 *
 * The schema is applied with `prisma migrate deploy` when the service has
 * migrations (this repo), otherwise with `prisma db push` (a fresh template).
 * The container uses an ephemeral port and is removed afterwards. Without
 * Docker the suite is skipped with a message.
 */
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { ConflictException } from '@nestjs/common';
import type { LoggerService, RedisService } from '@tsdevstack/nest-common';
import { PrismaService } from '../prisma/prisma.service';
import { ApiKeyIndexService } from './api-key-index.service';
import { ApiKeyUsageService } from './api-key-usage.service';
import { ApiKeysService } from './api-keys.service';
import type { ApiKeyRecordState, ApiKeyRecordWrite } from './api-keys.types';
import { formatApiKeyUsagePeriod } from './utils/format-api-key-usage-period';
import { isDockerAvailable } from '../../test/support/is-docker-available';
import {
  startTestContainer,
  type TestContainer,
} from '../../test/support/start-test-container';

jest.setTimeout(120_000);

const APP_ROOT = resolve(__dirname, '../..');

const silentLogger = (): LoggerService => {
  const logger = {
    child: () => logger,
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  };
  return logger as unknown as LoggerService;
};

if (!isDockerAvailable()) {
  describe('API key writes with Postgres (Docker)', () => {
    it.skip('SKIPPED: Docker is not running; start Docker to run the API key Postgres suite', () => {
      // Docker-backed suite (D16): skipped without Docker
    });
  });

  console.warn(
    'api-keys.postgres.spec: Docker is not running; the API key Postgres suite is SKIPPED',
  );
} else {
  describe('API key writes with Postgres 17', () => {
    let container: TestContainer;
    let prisma: PrismaService;
    let previousDatabaseUrl: string | undefined;
    let index: {
      writeRecord: jest.Mock;
      repairRecordWrite: jest.Mock;
      rebuildIfMissing: jest.Mock;
      isIndexPresent: jest.Mock;
    };
    let service: ApiKeysService;

    beforeAll(async () => {
      container = await startTestContainer(
        'auth-apikeys-pg-itest',
        [
          '-e',
          'POSTGRES_PASSWORD=test',
          '-e',
          'POSTGRES_DB=auth',
          'postgres:17',
          '-c',
          'timezone=Europe/Paris',
        ],
        5432,
        ['psql', '-U', 'postgres', '-d', 'auth', '-c', 'SELECT 1'],
      );
      const url = `postgresql://postgres:test@127.0.0.1:${container.port}/auth`;
      const migrate = existsSync(join(APP_ROOT, 'prisma', 'migrations'))
        ? ['prisma', 'migrate', 'deploy']
        : ['prisma', 'db', 'push'];
      execFileSync('npx', migrate, {
        cwd: APP_ROOT,
        env: { ...process.env, DATABASE_URL: url },
        stdio: 'pipe',
      });

      previousDatabaseUrl = process.env.DATABASE_URL;
      process.env.DATABASE_URL = url;
      prisma = new PrismaService();
      await prisma.user.create({
        data: {
          id: 'admin-1',
          email: 'admin@example.com',
          passwordHash: 'x',
          firstName: 'A',
          lastName: 'D',
        },
      });
    });

    afterAll(async () => {
      await prisma?.onModuleDestroy();
      process.env.DATABASE_URL = previousDatabaseUrl;
      container?.remove();
    });

    beforeEach(async () => {
      await prisma.apiKeyUsage.deleteMany();
      await prisma.apiKey.deleteMany();
      index = {
        writeRecord: jest.fn(
          (
            keyHash: string,
            state: ApiKeyRecordState,
          ): Promise<ApiKeyRecordWrite> =>
            Promise.resolve({
              key: keyHash,
              written: state?.value ?? null,
              previous: null,
              previousExpireAtMs: null,
            }),
        ),
        repairRecordWrite: jest.fn().mockResolvedValue(true),
        rebuildIfMissing: jest.fn().mockResolvedValue({
          status: 'present',
          recordsWritten: 0,
          countersSeeded: 0,
        }),
        isIndexPresent: jest.fn().mockResolvedValue(true),
      };
      service = new ApiKeysService(
        prisma,
        index as unknown as ApiKeyIndexService,
        silentLogger(),
      );
    });

    /** Runs `other` right after the next Redis write (a concurrent change) */
    const concurrently = (other: () => Promise<unknown>): void => {
      index.writeRecord.mockImplementationOnce(
        async (keyHash: string, state: ApiKeyRecordState) => {
          await other();
          return {
            key: keyHash,
            written: state?.value ?? null,
            previous: null,
            previousExpireAtMs: null,
          };
        },
      );
    };

    it('update: a change made after the read makes it a 409, and nothing of it is saved', async () => {
      const created = await service.create('admin-1', {
        name: 'n',
        consumer: 'acme-corp',
        limitPerMinute: 10,
      });
      concurrently(() =>
        prisma.apiKey.update({
          where: { id: created.id },
          data: { limitPerHour: 5 },
        }),
      );

      await expect(
        service.update(created.id, { limitPerMinute: 99 }),
      ).rejects.toBeInstanceOf(ConflictException);

      const row = await prisma.apiKey.findUniqueOrThrow({
        where: { id: created.id },
      });
      expect(row.limitPerMinute).toBe(10);
      expect(row.limitPerHour).toBe(5);
      expect(index.repairRecordWrite).toHaveBeenCalledTimes(1);
    });

    it('update: an unchanged row is updated and its updatedAt moves forward', async () => {
      const created = await service.create('admin-1', {
        name: 'n',
        consumer: 'acme-corp',
      });
      const before = await prisma.apiKey.findUniqueOrThrow({
        where: { id: created.id },
      });

      const updated = await service.update(created.id, { limitPerDay: 3 });

      expect(updated.limitPerDay).toBe(3);
      expect(updated.updatedAt.getTime()).toBeGreaterThan(
        before.updatedAt.getTime(),
      );
      await expect(
        service.update(created.id, { limitPerDay: 4 }),
      ).resolves.toMatchObject({ limitPerDay: 4 });
    });

    it('revoke after a concurrent revoke is a 409; the row stays revoked', async () => {
      const created = await service.create('admin-1', {
        name: 'n',
        consumer: 'acme-corp',
      });
      concurrently(() => service.revoke(created.id));

      await expect(service.revoke(created.id)).rejects.toBeInstanceOf(
        ConflictException,
      );
      const row = await prisma.apiKey.findUniqueOrThrow({
        where: { id: created.id },
      });
      expect(row.status).toBe('REVOKED');
      expect(row.revokedAt).toBeInstanceOf(Date);
    });

    it('rotate that loses against a revoke rolls back the new key', async () => {
      const created = await service.create('admin-1', {
        name: 'n',
        consumer: 'acme-corp',
      });
      concurrently(() => service.revoke(created.id));

      await expect(
        service.rotate('admin-1', created.id, 1),
      ).rejects.toBeInstanceOf(ConflictException);

      expect(await prisma.apiKey.count()).toBe(1);
      expect(
        (await prisma.apiKey.findUniqueOrThrow({ where: { id: created.id } }))
          .status,
      ).toBe('REVOKED');
    });

    it('rotate on an unchanged key creates the new key and shortens the old one', async () => {
      const created = await service.create('admin-1', {
        name: 'n',
        consumer: 'acme-corp',
      });
      const rotated = await service.rotate('admin-1', created.id, 1);
      expect(await prisma.apiKey.count()).toBe(2);
      expect(rotated.previousKey.expiresAt).toBeInstanceOf(Date);
      expect(rotated.newKey.expiresAt).toBeNull();
    });

    describe('Usage totals (BIGINT)', () => {
      let keyId: string;
      let counts: (string | null)[];
      let usageService: ApiKeyUsageService;

      beforeEach(async () => {
        keyId = (
          await service.create('admin-1', { name: 'n', consumer: 'acme-corp' })
        ).id;
        counts = [null, null, null, null, null];
        const redis = {
          getClient: () => ({
            pipeline: () => {
              const replies: [null, (string | null)[]][] = [];
              const pipeline = {
                mget: () => {
                  replies.push([null, counts]);
                  return pipeline;
                },
                exec: () => Promise.resolve(replies),
              };
              return pipeline;
            },
          }),
        } as unknown as RedisService;
        usageService = new ApiKeyUsageService(
          redis,
          prisma,
          index as unknown as ApiKeyIndexService,
          silentLogger(),
        );
      });

      const saved = async (period: string): Promise<bigint | undefined> =>
        (
          await prisma.apiKeyUsage.findUnique({
            where: { keyId_period: { keyId, period } },
          })
        )?.count;

      it('stores totals above 2^31 and above 2^53 exactly, and never lowers them', async () => {
        const now = Math.floor(Date.now() / 1000);
        const week = formatApiKeyUsagePeriod('week', now);
        const month = formatApiKeyUsagePeriod('month', now);
        // [current week, previous week, current month, previous month, lu]
        counts = ['2147483648', null, '9007199254740993', null, null];

        await usageService.sync();
        expect(await saved(week)).toBe(2_147_483_648n);
        expect(await saved(month)).toBe(9_007_199_254_740_993n);

        counts = ['5', null, '9223372036854775807', null, null];
        await usageService.sync();
        expect(await saved(week)).toBe(2_147_483_648n);
        expect(await saved(month)).toBe(9_223_372_036_854_775_807n);

        await expect(service.usage(keyId)).resolves.toEqual(
          expect.arrayContaining([
            { period: week, count: 2_147_483_648 },
            { period: month, count: '9223372036854775807' },
          ]),
        );
      });

      it('moves lastUsedAt forward only, in UTC, without touching updatedAt', async () => {
        const before = await prisma.apiKey.findUniqueOrThrow({
          where: { id: keyId },
        });
        const at = Math.floor(Date.now() / 1000) - 60;

        counts = [null, null, null, null, String(at)];
        await usageService.sync();
        counts = [null, null, null, null, String(at - 3600)];
        await usageService.sync();

        const row = await prisma.apiKey.findUniqueOrThrow({
          where: { id: keyId },
        });
        expect(row.lastUsedAt?.getTime()).toBe(at * 1000);
        expect(row.updatedAt.getTime()).toBe(before.updatedAt.getTime());
      });
    });
  });
}
