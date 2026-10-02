/**
 * API key index against a real Redis (Docker), in standalone and in
 * cluster mode (a one-node cluster still rejects cross-slot multi-key
 * commands with CROSSSLOT, like Azure's clustered Redis).
 *
 * Postgres is an in-memory stand-in with conditional updates, interactive
 * transactions and failure injection (test/support/fake-api-key-prisma.ts);
 * the real conditional update and BIGINT run in api-keys.postgres.spec.ts.
 * Redis semantics (NX, TTLs, scripts, hash slots) are real. Each suite
 * starts its own container on an ephemeral port and removes it afterwards.
 * Without Docker the suite is skipped with a message.
 */
import Redis from 'ioredis';
import { ConflictException, ServiceUnavailableException } from '@nestjs/common';
import {
  API_KEY_INDEX_MARKER_KEY,
  API_KEY_REBUILD_LOCK_KEY,
  buildApiKeyCounterKey,
  buildApiKeyLastUsedKey,
  buildApiKeyRecordKey,
  decodeApiKeyRecord,
  getApiKeyCounterExpireAt,
  hashApiKey,
} from '@tsdevstack/nest-common';
import type {
  LoggerService,
  RedisReadyListener,
  RedisService,
} from '@tsdevstack/nest-common';
import type { ApiKey } from '../generated/prisma/client';
import type { PrismaService } from '../prisma/prisma.service';
import { ApiKeyIndexService } from './api-key-index.service';
import { ApiKeyUsageService } from './api-key-usage.service';
import { ApiKeysService } from './api-keys.service';
import type { ApiKeyRecordState, ApiKeyRecordWrite } from './api-keys.types';
import { buildApiKeySeedFlagKey } from './utils/build-api-key-seed-flag-key';
import { formatApiKeyUsagePeriod } from './utils/format-api-key-usage-period';
import { resolveApiKeyRecordState } from './utils/resolve-api-key-record-state';
import { FakeApiKeyPrisma } from '../../test/support/fake-api-key-prisma';
import { isDockerAvailable } from '../../test/support/is-docker-available';
import { runDocker } from '../../test/support/run-docker';
import {
  startTestContainer,
  type TestContainer,
} from '../../test/support/start-test-container';

jest.setTimeout(60_000);

const DAY = 86_400;

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

async function startRedis(cluster: boolean): Promise<TestContainer> {
  const container = await startTestContainer(
    'auth-apikeys-redis-itest',
    [
      'redis:7-alpine',
      'redis-server',
      '--save',
      '',
      '--appendonly',
      'no',
      ...(cluster ? ['--cluster-enabled', 'yes'] : []),
    ],
    6379,
    ['redis-cli', 'ping'],
  );
  if (cluster) {
    runDocker(
      'exec',
      container.name,
      'redis-cli',
      'cluster',
      'addslotsrange',
      '0',
      '16383',
    );
    const deadline = Date.now() + 30_000;
    while (
      !runDocker(
        'exec',
        container.name,
        'redis-cli',
        'cluster',
        'info',
      ).includes('cluster_state:ok')
    ) {
      if (Date.now() > deadline) {
        container.remove();
        throw new Error('Cluster did not become ok');
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }
  return container;
}

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
  describe('API key index with Redis (Docker)', () => {
    it.skip('SKIPPED: Docker is not running; start Docker to run the API key Redis suite', () => {
      // Docker-backed suite (D16): skipped without Docker
    });
  });

  console.warn(
    'api-keys.redis.spec: Docker is not running; the API key Redis suite is SKIPPED',
  );
} else {
  describe.each([
    ['standalone', false],
    ['cluster mode', true],
  ])('API key index with Redis (%s)', (_label, cluster) => {
    let container: TestContainer;
    let client: Redis;
    let prisma: FakeApiKeyPrisma;
    let index: ApiKeyIndexService;
    let service: ApiKeysService;
    let usageService: ApiKeyUsageService;
    let redisService: RedisService;
    let readyListeners: RedisReadyListener[];

    beforeAll(async () => {
      container = await startRedis(cluster);
      client = new Redis({
        host: '127.0.0.1',
        port: container.port,
        enableOfflineQueue: false,
        maxRetriesPerRequest: 1,
      });
      await new Promise<void>((resolve) =>
        client.once('ready', () => resolve()),
      );
    }, 120_000);

    afterAll(() => {
      client?.disconnect();
      container?.remove();
    });

    beforeEach(async () => {
      await client.flushall();
      prisma = new FakeApiKeyPrisma();
      readyListeners = [];
      redisService = {
        getClient: () => client,
        isReady: () => true,
        onReady: (listener: RedisReadyListener) => {
          readyListeners.push(listener);
          return () => undefined;
        },
      } as unknown as RedisService;
      const logger = silentLogger();
      index = new ApiKeyIndexService(
        redisService,
        prisma as unknown as PrismaService,
        logger,
      );
      index.onModuleInit();
      service = new ApiKeysService(
        prisma as unknown as PrismaService,
        index,
        logger,
      );
      usageService = new ApiKeyUsageService(
        redisService,
        prisma as unknown as PrismaService,
        index,
        logger,
      );
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    const record = async (keyHash: string): Promise<string | null> =>
      await client.get(buildApiKeyRecordKey(keyHash));

    const expectedValue = (row: ApiKey): string | null =>
      resolveApiKeyRecordState(row, nowSeconds())?.value ?? null;

    /** Redis holds exactly the record resolved from every database row */
    const expectRedisMatchesDatabase = async (): Promise<void> => {
      for (const row of prisma.keys.values()) {
        expect(await record(row.keyHash)).toBe(expectedValue(row));
      }
    };

    /** What Kong does on an admitted request for the quota windows */
    const kongCounts = async (
      keyHash: string,
      times: number,
    ): Promise<void> => {
      const now = nowSeconds();
      for (const window of ['week', 'month'] as const) {
        const key = buildApiKeyCounterKey(keyHash, window, now);
        await client.incrby(key, times);
        if ((await client.ttl(key)) === -1) {
          await client.expireat(key, getApiKeyCounterExpireAt(window, now));
        }
      }
    };

    /**
     * Runs `hook` once, around the first Redis record write made after this
     * call: `before` it (the operation read a snapshot that is now stale) or
     * `after` it (the Redis write is done, Postgres is not).
     */
    const aroundFirstWrite = (
      when: 'before' | 'after',
      hook: () => Promise<unknown>,
    ): void => {
      const original = index.writeRecord.bind(
        index,
      ) as ApiKeyIndexService['writeRecord'];
      let fired = false;
      jest
        .spyOn(index, 'writeRecord')
        .mockImplementation(
          async (
            keyHash: string,
            state: ApiKeyRecordState,
          ): Promise<ApiKeyRecordWrite> => {
            if (fired) return original(keyHash, state);
            fired = true;
            if (when === 'before') await hook();
            const write = await original(keyHash, state);
            if (when === 'after') await hook();
            return write;
          },
        );
    };

    describe('Writes', () => {
      it('create writes the full record (no TTL) and returns the key once', async () => {
        const created = await service.create('admin-1', {
          name: 'Integration',
          consumer: 'acme-corp',
          limitPerMinute: 60,
          limitPerMonth: 1000,
        });

        const hash = hashApiKey(created.key);
        expect(created.key).toMatch(/^tsk_[A-Za-z0-9_-]{43}$/);
        expect(created.prefix).toBe(created.key.slice(0, 12));
        expect(decodeApiKeyRecord((await record(hash)) as string)).toEqual({
          v: 1,
          id: created.id,
          consumer: 'acme-corp',
          status: 'active',
          limits: { minute: 60, month: 1000 },
        });
        expect(await client.ttl(buildApiKeyRecordKey(hash))).toBe(-1);
        expect(prisma.keys.get(created.id)?.keyHash).toBe(hash);
        expect(JSON.stringify([...prisma.keys.values()])).not.toContain(
          created.key,
        );
      });

      it('an expiring key keeps its record until one day after expiry', async () => {
        const expiresAt = new Date((nowSeconds() + 3600) * 1000);
        const created = await service.create('admin-1', {
          name: 'Trial',
          consumer: 'trial-co',
          expiresAt: expiresAt.toISOString(),
        });
        const key = buildApiKeyRecordKey(hashApiKey(created.key));
        expect(await client.call('EXPIRETIME', key)).toBe(
          Math.floor(expiresAt.getTime() / 1000) + DAY,
        );
      });

      it('update rewrites the full record; clearing the expiry removes the TTL', async () => {
        const { row } = prisma.seedKey({
          expiresAt: new Date((nowSeconds() + 3600) * 1000),
        });
        await client.set(
          buildApiKeyRecordKey(row.keyHash),
          expectedValue(row) as string,
          'EXAT',
          nowSeconds() + 3600 + DAY,
        );

        await service.update(row.id, {
          limitPerMinute: null,
          limitPerDay: 500,
          expiresAt: null,
        });

        const stored = decodeApiKeyRecord(
          (await record(row.keyHash)) as string,
        );
        expect(stored.limits).toEqual({ day: 500 });
        expect(stored.expiresAt).toBeUndefined();
        expect(await client.ttl(buildApiKeyRecordKey(row.keyHash))).toBe(-1);
      });

      it('an expiry more than a day in the past removes the record', async () => {
        const { row } = prisma.seedKey();
        await client.set(
          buildApiKeyRecordKey(row.keyHash),
          expectedValue(row) as string,
        );
        await service.update(row.id, {
          expiresAt: new Date((nowSeconds() - 3 * DAY) * 1000).toISOString(),
        });
        expect(await record(row.keyHash)).toBeNull();
      });

      it('revoke writes a revoked record that expires one day after revokedAt', async () => {
        const { row } = prisma.seedKey();
        await client.set(
          buildApiKeyRecordKey(row.keyHash),
          expectedValue(row) as string,
        );

        const revoked = await service.revoke(row.id);

        expect(revoked.status).toBe('REVOKED');
        const stored = decodeApiKeyRecord(
          (await record(row.keyHash)) as string,
        );
        expect(stored.status).toBe('revoked');
        const revokedAt = prisma.keys.get(row.id)?.revokedAt as Date;
        expect(
          await client.call('EXPIRETIME', buildApiKeyRecordKey(row.keyHash)),
        ).toBe(Math.floor(revokedAt.getTime() / 1000) + DAY);
      });

      it('revoking a revoked key rewrites its record without extending it (repair path)', async () => {
        const revokedAt = new Date((nowSeconds() - 3600) * 1000);
        const { row } = prisma.seedKey({ status: 'REVOKED', revokedAt });
        // Redis was left behind: it still has the active record
        await client.set(
          buildApiKeyRecordKey(row.keyHash),
          expectedValue({
            ...row,
            status: 'ACTIVE',
            revokedAt: null,
          }) as string,
        );

        await service.revoke(row.id);

        expect(
          decodeApiKeyRecord((await record(row.keyHash)) as string).status,
        ).toBe('revoked');
        expect(
          await client.call('EXPIRETIME', buildApiKeyRecordKey(row.keyHash)),
        ).toBe(nowSeconds() - 3600 + DAY);
        expect(prisma.writes).toBe(0);
      });

      it('rotate issues a new record and shortens the old expiry to the grace', async () => {
        const { row } = prisma.seedKey({ limitPerHour: 100 });
        await client.set(
          buildApiKeyRecordKey(row.keyHash),
          expectedValue(row) as string,
        );

        const before = nowSeconds();
        const rotated = await service.rotate('admin-2', row.id, 2);

        const fresh = decodeApiKeyRecord(
          (await record(hashApiKey(rotated.newKey.key))) as string,
        );
        expect(fresh).toEqual({
          v: 1,
          id: rotated.newKey.id,
          consumer: 'acme-corp',
          status: 'active',
          limits: { minute: 10, hour: 100 },
        });
        const old = decodeApiKeyRecord((await record(row.keyHash)) as string);
        expect(old.status).toBe('active');
        expect(old.expiresAt).toBeGreaterThanOrEqual(before + 2 * 3600);
        expect(old.expiresAt).toBeLessThanOrEqual(nowSeconds() + 2 * 3600);
        expect(rotated.previousKey.expiresAt?.getTime()).toBe(
          prisma.keys.get(row.id)?.expiresAt?.getTime(),
        );
        await expectRedisMatchesDatabase();
      });
    });

    describe('Postgres failure repairs Redis from the database', () => {
      it('create: no record is left behind', async () => {
        prisma.failures.push('create');
        await expect(
          service.create('admin-1', { name: 'x', consumer: 'acme-corp' }),
        ).rejects.toThrow('simulated Postgres failure');
        expect(await client.keys('apikey:*')).toEqual([]);
        expect(prisma.keys.size).toBe(0);
      });

      it('update: the record goes back to the database state', async () => {
        const { row } = prisma.seedKey({
          expiresAt: new Date((nowSeconds() + 7200) * 1000),
        });
        const key = buildApiKeyRecordKey(row.keyHash);
        await client.set(key, expectedValue(row) as string);

        prisma.failures.push('transaction');
        await expect(
          service.update(row.id, { limitPerMinute: 999 }),
        ).rejects.toThrow('simulated Postgres failure');

        expect(await client.get(key)).toBe(expectedValue(row));
        expect(await client.call('EXPIRETIME', key)).toBe(
          Math.floor((row.expiresAt as Date).getTime() / 1000) + DAY,
        );
      });

      it('revoke: the active record comes back without a TTL', async () => {
        const { row } = prisma.seedKey();
        const key = buildApiKeyRecordKey(row.keyHash);
        await client.set(key, expectedValue(row) as string);

        prisma.failures.push('transaction');
        await expect(service.revoke(row.id)).rejects.toThrow();

        expect(
          decodeApiKeyRecord((await client.get(key)) as string).status,
        ).toBe('active');
        expect(await client.ttl(key)).toBe(-1);
        expect(prisma.keys.get(row.id)?.status).toBe('ACTIVE');
      });

      it('rotate: the new record is removed and the old one restored', async () => {
        const { row } = prisma.seedKey();
        const key = buildApiKeyRecordKey(row.keyHash);
        await client.set(key, expectedValue(row) as string);

        prisma.failures.push('transaction');
        await expect(service.rotate('admin-1', row.id)).rejects.toThrow();

        expect(await client.keys('apikey:*')).toEqual([key]);
        expect(await client.get(key)).toBe(expectedValue(row));
        expect(await client.ttl(key)).toBe(-1);
        expect(prisma.keys.size).toBe(1);
      });

      it('a repair never overwrites a newer change by someone else', async () => {
        const { row } = prisma.seedKey();
        const key = buildApiKeyRecordKey(row.keyHash);
        await client.set(key, expectedValue(row) as string);

        const write = await index.writeRecord(
          row.keyHash,
          resolveApiKeyRecordState({ ...row, limitPerMinute: 1 }, nowSeconds()),
        );
        const newer = resolveApiKeyRecordState(
          { ...row, limitPerMinute: 2 },
          nowSeconds(),
        );
        await index.writeRecord(row.keyHash, newer);

        await index.repairRecordWrite(write, () =>
          Promise.resolve(resolveApiKeyRecordState(row, nowSeconds())),
        );
        expect(await client.get(key)).toBe(newer?.value);
        expect(await index.undoRecordWrite(write)).toBe(false);
        expect(await client.get(key)).toBe(newer?.value);
      });

      describe('interleaved with a rebuild (Redis had lost its data)', () => {
        it('update: the key keeps a working record (was deleted before)', async () => {
          const { row } = prisma.seedKey(); // marker and record missing
          prisma.failures.push('transaction');
          aroundFirstWrite('after', () =>
            index.rebuildIfMissing('redis-ready'),
          );

          await expect(
            service.update(row.id, { limitPerMinute: 99 }),
          ).rejects.toThrow('simulated Postgres failure');

          expect(await client.exists(API_KEY_INDEX_MARKER_KEY)).toBe(1);
          expect(await record(row.keyHash)).toBe(expectedValue(row));
        });

        it('revoke: the key keeps its active record, as in the database', async () => {
          const { row } = prisma.seedKey();
          prisma.failures.push('transaction');
          aroundFirstWrite('after', () =>
            index.rebuildIfMissing('redis-ready'),
          );

          await expect(service.revoke(row.id)).rejects.toThrow();

          expect(await record(row.keyHash)).toBe(expectedValue(row));
        });

        it('create: the unsaved key has no record', async () => {
          prisma.seedKey();
          prisma.failures.push('create');
          aroundFirstWrite('after', () =>
            index.rebuildIfMissing('redis-ready'),
          );

          await expect(
            service.create('admin-1', { name: 'n', consumer: 'new-co' }),
          ).rejects.toThrow();

          expect(prisma.keys.size).toBe(1);
          await expectRedisMatchesDatabase();
          expect(await client.keys('apikey:{*}:rec')).toHaveLength(1);
        });
      });

      describe('ambiguous failure (Postgres committed, then reported an error)', () => {
        it('revoke: the key stays revoked', async () => {
          const { row } = prisma.seedKey();
          await client.set(
            buildApiKeyRecordKey(row.keyHash),
            expectedValue(row) as string,
          );
          prisma.failures.push('commit-then-fail');

          await expect(service.revoke(row.id)).rejects.toThrow('after commit');

          expect(prisma.keys.get(row.id)?.status).toBe('REVOKED');
          expect(
            decodeApiKeyRecord((await record(row.keyHash)) as string).status,
          ).toBe('revoked');
          await expectRedisMatchesDatabase();
        });

        it('update and create: Redis follows the committed rows', async () => {
          const { row } = prisma.seedKey();
          prisma.failures.push('commit-then-fail');
          await expect(
            service.update(row.id, { limitPerDay: 7 }),
          ).rejects.toThrow();
          expect(prisma.keys.get(row.id)?.limitPerDay).toBe(7);

          jest.spyOn(prisma.apiKey, 'create').mockImplementationOnce((args) => {
            prisma.keys.set(args.data.id, {
              lastUsedAt: null,
              revokedAt: null,
              createdAt: new Date(),
              updatedAt: new Date(),
              ...args.data,
            } as ApiKey);
            return Promise.reject(
              new Error('connection lost after the insert'),
            );
          });
          await expect(
            service.create('admin-1', { name: 'n', consumer: 'new-co' }),
          ).rejects.toThrow('connection lost');

          expect(prisma.keys.size).toBe(2);
          await expectRedisMatchesDatabase();
        });
      });

      describe('the re-read fails too (fallback)', () => {
        it('revoke: the revoked record is kept (safe direction)', async () => {
          const { row } = prisma.seedKey();
          await client.set(
            buildApiKeyRecordKey(row.keyHash),
            expectedValue(row) as string,
          );
          prisma.failures.push('transaction');
          aroundFirstWrite('after', () => {
            prisma.failures.push('findUnique');
            return Promise.resolve();
          });

          await expect(service.revoke(row.id)).rejects.toThrow();

          expect(
            decodeApiKeyRecord((await record(row.keyHash)) as string).status,
          ).toBe('revoked');
        });

        it('update: the previous value and its exact expiry are restored', async () => {
          const { row } = prisma.seedKey();
          const key = buildApiKeyRecordKey(row.keyHash);
          const previous = expectedValue(row) as string;
          await client.set(key, previous, 'PXAT', Date.now() + 5_000_000);
          const previousAt = await client.call('PEXPIRETIME', key);
          prisma.failures.push('transaction');
          aroundFirstWrite('after', () => {
            prisma.failures.push('findUnique');
            return Promise.resolve();
          });

          await expect(
            service.update(row.id, { limitPerMinute: 1 }),
          ).rejects.toThrow();

          expect(await client.get(key)).toBe(previous);
          expect(await client.call('PEXPIRETIME', key)).toBe(previousAt);
        });
      });
    });

    describe('Concurrent admin operations on the same key', () => {
      type Operation = 'update' | 'revoke' | 'rotate';
      const run = (operation: Operation, id: string): Promise<unknown> =>
        operation === 'update'
          ? service.update(id, { limitPerMinute: 77 })
          : operation === 'revoke'
            ? service.revoke(id)
            : service.rotate('admin-1', id, 1);

      const pairs: [Operation, Operation][] = [
        ['update', 'revoke'],
        ['revoke', 'update'],
        ['rotate', 'revoke'],
        ['revoke', 'rotate'],
      ];

      describe.each(['before', 'after'] as const)(
        'the second operation runs %s the first one writes Redis',
        (when) => {
          it.each(pairs)(
            '%s loses against %s with 409; Redis matches Postgres',
            async (first, second) => {
              const { row } = prisma.seedKey();
              await client.set(
                buildApiKeyRecordKey(row.keyHash),
                expectedValue(row) as string,
              );
              aroundFirstWrite(when, () => run(second, row.id));

              await expect(run(first, row.id)).rejects.toBeInstanceOf(
                ConflictException,
              );

              await expectRedisMatchesDatabase();
              if (second === 'revoke') {
                expect(prisma.keys.get(row.id)?.status).toBe('REVOKED');
                expect(
                  decodeApiKeyRecord((await record(row.keyHash)) as string)
                    .status,
                ).toBe('revoked');
              } else {
                expect(prisma.keys.get(row.id)?.status).toBe('ACTIVE');
              }
            },
          );
        },
      );

      it('a revoked key cannot be revived by an update that read it active', async () => {
        const { row } = prisma.seedKey();
        aroundFirstWrite('before', () => service.revoke(row.id));
        await expect(
          service.update(row.id, { limitPerMinute: 5 }),
        ).rejects.toBeInstanceOf(ConflictException);
        // A later rebuild does not revive it either
        await client.del(API_KEY_INDEX_MARKER_KEY);
        await index.rebuildIfMissing('test');
        expect(
          decodeApiKeyRecord((await record(row.keyHash)) as string).status,
        ).toBe('revoked');
      });
    });

    describe('Redis failure leaves Postgres untouched', () => {
      let deadClient: Redis;

      beforeEach(() => {
        deadClient = new Redis({
          host: '127.0.0.1',
          port: container.port,
          lazyConnect: true,
          enableOfflineQueue: false,
          retryStrategy: () => null,
        });
        (redisService as unknown as { getClient: () => Redis }).getClient =
          () => deadClient;
      });

      afterEach(() => deadClient.disconnect());

      it('create, update, revoke and rotate fail with 503 before touching Postgres', async () => {
        const { row } = prisma.seedKey();
        const snapshot = JSON.stringify([...prisma.keys.values()]);

        await expect(
          service.create('admin-1', { name: 'x', consumer: 'acme-corp' }),
        ).rejects.toBeInstanceOf(ServiceUnavailableException);
        await expect(
          service.update(row.id, { limitPerMinute: 5 }),
        ).rejects.toBeInstanceOf(ServiceUnavailableException);
        await expect(service.revoke(row.id)).rejects.toBeInstanceOf(
          ServiceUnavailableException,
        );
        await expect(service.rotate('admin-1', row.id)).rejects.toBeInstanceOf(
          ServiceUnavailableException,
        );

        expect(prisma.writes).toBe(0);
        expect(JSON.stringify([...prisma.keys.values()])).toBe(snapshot);
      });

      it('rotate: a failed second write removes the first and leaves Postgres alone', async () => {
        (redisService as unknown as { getClient: () => Redis }).getClient =
          () => client;
        const { row } = prisma.seedKey();
        const key = buildApiKeyRecordKey(row.keyHash);
        await client.set(key, expectedValue(row) as string);

        const original = index.writeRecord.bind(
          index,
        ) as ApiKeyIndexService['writeRecord'];
        let calls = 0;
        jest.spyOn(index, 'writeRecord').mockImplementation((hash, state) => {
          calls += 1;
          return calls === 2
            ? Promise.reject(new Error('Connection is closed.'))
            : original(hash, state);
        });

        await expect(service.rotate('admin-1', row.id)).rejects.toBeInstanceOf(
          ServiceUnavailableException,
        );
        expect(await client.keys('apikey:*')).toEqual([key]);
        expect(prisma.writes).toBe(0);
      });
    });

    describe('Rebuild', () => {
      it('restores active, unexpired keys and writes the marker last', async () => {
        const active = prisma.seedKey().row;
        const expiring = prisma.seedKey({
          expiresAt: new Date((nowSeconds() + 3600) * 1000),
        }).row;
        const revoked = prisma.seedKey({
          status: 'REVOKED',
          revokedAt: new Date(),
        }).row;
        const expired = prisma.seedKey({
          expiresAt: new Date((nowSeconds() - 60) * 1000),
        }).row;

        const result = await index.rebuildIfMissing('test');

        expect(result).toEqual({
          status: 'rebuilt',
          recordsWritten: 2,
          countersSeeded: 0,
        });
        expect(await record(active.keyHash)).toBe(expectedValue(active));
        expect(await record(expiring.keyHash)).toBe(expectedValue(expiring));
        expect(
          await client.call(
            'EXPIRETIME',
            buildApiKeyRecordKey(expiring.keyHash),
          ),
        ).toBe(Math.floor((expiring.expiresAt as Date).getTime() / 1000) + DAY);
        expect(await record(revoked.keyHash)).toBeNull();
        expect(await record(expired.keyHash)).toBeNull();
        expect(await client.exists(API_KEY_INDEX_MARKER_KEY)).toBe(1);
        expect(await client.exists(API_KEY_REBUILD_LOCK_KEY)).toBe(0);
      });

      it('does nothing while the marker exists', async () => {
        const { row } = prisma.seedKey();
        await client.set(API_KEY_INDEX_MARKER_KEY, '{}');
        expect((await index.rebuildIfMissing('test')).status).toBe('present');
        expect(await record(row.keyHash)).toBeNull();
      });

      it('stays out while another instance holds the lock', async () => {
        prisma.seedKey();
        await client.set(
          API_KEY_REBUILD_LOCK_KEY,
          'other-instance',
          'PX',
          60_000,
        );
        expect((await index.rebuildIfMissing('test')).status).toBe('locked');
        expect(await client.exists(API_KEY_INDEX_MARKER_KEY)).toBe(0);
        expect(await client.get(API_KEY_REBUILD_LOCK_KEY)).toBe(
          'other-instance',
        );
      });

      it('never overwrites an existing record', async () => {
        const { row } = prisma.seedKey();
        await client.set(
          buildApiKeyRecordKey(row.keyHash),
          'newer-by-an-admin',
        );
        await index.rebuildIfMissing('test');
        expect(await record(row.keyHash)).toBe('newer-by-an-admin');
      });

      it('loads keys in batches', async () => {
        const rows = Array.from({ length: 3 }, () => prisma.seedKey().row);
        const spy = jest.spyOn(index, 'loadRebuildBatch');
        await index.rebuildIfMissing('test');
        for (const row of rows) {
          expect(await record(row.keyHash)).toBe(expectedValue(row));
        }
        expect(spy).toHaveBeenLastCalledWith(
          [...rows].sort((a, b) => (a.id < b.id ? -1 : 1))[2].id,
          expect.any(Number),
        );
      });
    });

    describe('Rebuild interrupted by a Redis restart or a lost lock', () => {
      /** Runs `during` once, after the first batch was written */
      const duringRebuild = (during: () => Promise<unknown>): void => {
        const original = index.writeRebuildBatch.bind(
          index,
        ) as ApiKeyIndexService['writeRebuildBatch'];
        let fired = false;
        jest
          .spyOn(index, 'writeRebuildBatch')
          .mockImplementation(async (rows, now) => {
            const result = await original(rows, now);
            if (!fired) {
              fired = true;
              await during();
            }
            return result;
          });
      };

      it('Redis restarted empty mid-run: no marker over missing records', async () => {
        const { row } = prisma.seedKey();
        duringRebuild(async () => {
          // What a restart without persistence leaves: nothing, and the
          // client's connection dropped
          await client.flushall();
          await client
            .client('KILL', 'TYPE', 'normal', 'SKIPME', 'no')
            .catch(() => undefined);
          await new Promise((resolve) => setTimeout(resolve, 300));
          const deadline = Date.now() + 10_000;
          while (client.status !== 'ready' && Date.now() < deadline) {
            await new Promise((resolve) => setTimeout(resolve, 50));
          }
        });

        const result = await index.rebuildIfMissing('startup');

        expect(result.status).toBe('interrupted');
        expect(await client.exists(API_KEY_INDEX_MARKER_KEY)).toBe(0);
        expect(await record(row.keyHash)).toBeNull();

        // The next trigger (reconnect, job) rebuilds for real
        jest.restoreAllMocks();
        expect((await index.rebuildIfMissing('usage-job')).status).toBe(
          'rebuilt',
        );
        expect(await record(row.keyHash)).toBe(expectedValue(row));
      });

      it('lock expired and taken by another instance: no marker from this run', async () => {
        prisma.seedKey();
        duringRebuild(() =>
          client.set(API_KEY_REBUILD_LOCK_KEY, 'other-instance', 'PX', 60_000),
        );

        expect((await index.rebuildIfMissing('startup')).status).toBe(
          'interrupted',
        );
        expect(await client.exists(API_KEY_INDEX_MARKER_KEY)).toBe(0);
        expect(await client.get(API_KEY_REBUILD_LOCK_KEY)).toBe(
          'other-instance',
        );
      });

      it('Redis reconnected mid-run: marker skipped, exactly one follow-up run', async () => {
        const { row } = prisma.seedKey();
        const firstBatches = jest.spyOn(index, 'loadRebuildBatch');
        duringRebuild(async () => {
          // A reconnect fires `ready`; more triggers arrive meanwhile
          for (const listener of readyListeners) await listener();
          void index.rebuildIfMissing('usage-job');
          void index.rebuildIfMissing('startup');
        });

        const result = await index.rebuildIfMissing('startup');

        expect(result.status).toBe('rebuilt');
        const runs = firstBatches.mock.calls.filter(
          ([afterId]) => afterId === null,
        );
        expect(runs).toHaveLength(2);
        expect(await client.exists(API_KEY_INDEX_MARKER_KEY)).toBe(1);
        expect(await record(row.keyHash)).toBe(expectedValue(row));
      });
    });

    describe('Rebuild interleaved with admin operations', () => {
      type Point = 'before' | 'after-load' | 'after-write' | 'after-marker';
      const points: Point[] = [
        'before',
        'after-load',
        'after-write',
        'after-marker',
      ];

      /** Runs a rebuild and performs `operation` at `point` */
      async function rebuildWith(
        point: Point,
        operation: () => Promise<unknown>,
      ): Promise<void> {
        if (point === 'before') {
          await operation();
          await index.rebuildIfMissing('test');
          return;
        }
        const method =
          point === 'after-load'
            ? 'loadRebuildBatch'
            : point === 'after-write'
              ? 'writeRebuildBatch'
              : 'writeMarker';
        const original = (
          index[method] as (...args: unknown[]) => Promise<unknown>
        ).bind(index) as (...args: unknown[]) => Promise<unknown>;
        let done = false;
        jest
          .spyOn(index, method)
          .mockImplementation(async (...args: unknown[]) => {
            const result = await original(...args);
            if (!done) {
              done = true;
              await operation();
            }
            return result as never;
          });
        await index.rebuildIfMissing('test');
        expect(done).toBe(true);
      }

      it.each(points)(
        'create at %s: the new key works afterwards',
        async (point) => {
          prisma.seedKey();
          let created: { id: string; key: string } | undefined;
          await rebuildWith(point, async () => {
            created = await service.create('admin-1', {
              name: 'new',
              consumer: 'new-co',
              limitPerDay: 7,
            });
          });
          const row = prisma.keys.get(created?.id as string) as ApiKey;
          expect(await record(row.keyHash)).toBe(expectedValue(row));
          expect(await client.exists(API_KEY_INDEX_MARKER_KEY)).toBe(1);
        },
      );

      it.each(points)('update at %s: the newer limits win', async (point) => {
        const { row } = prisma.seedKey({ limitPerMinute: 10 });
        await rebuildWith(point, () =>
          service.update(row.id, { limitPerMinute: 20 }),
        );
        const stored = decodeApiKeyRecord(
          (await record(row.keyHash)) as string,
        );
        expect(stored.limits.minute).toBe(20);
        await expectRedisMatchesDatabase();
      });

      it.each(points)('revoke at %s: the key stays revoked', async (point) => {
        const { row } = prisma.seedKey();
        await rebuildWith(point, () => service.revoke(row.id));
        const stored = decodeApiKeyRecord(
          (await record(row.keyHash)) as string,
        );
        expect(stored.status).toBe('revoked');
        expect(
          await client.ttl(buildApiKeyRecordKey(row.keyHash)),
        ).toBeGreaterThan(DAY - 60);
      });

      it('revoke during a rebuild stays revoked even after a second rebuild', async () => {
        const { row } = prisma.seedKey();
        await rebuildWith('after-load', () => service.revoke(row.id));
        await client.del(API_KEY_INDEX_MARKER_KEY);
        await index.rebuildIfMissing('test');
        expect(
          decodeApiKeyRecord((await record(row.keyHash)) as string).status,
        ).toBe('revoked');
      });
    });

    describe('Counters after a wipe', () => {
      it('equal the saved total plus the usage since the restart', async () => {
        const { row } = prisma.seedKey();
        const now = nowSeconds();
        prisma.setUsage(row.id, formatApiKeyUsagePeriod('week', now), 100n);
        prisma.setUsage(row.id, formatApiKeyUsagePeriod('month', now), 500n);

        await client.flushall(); // Redis lost everything
        await kongCounts(row.keyHash, 3); // Kong counted a few calls since

        const result = await index.rebuildIfMissing('redis-ready');
        expect(result.countersSeeded).toBe(2);

        const weekKey = buildApiKeyCounterKey(row.keyHash, 'week', now);
        const monthKey = buildApiKeyCounterKey(row.keyHash, 'month', now);
        expect(await client.get(weekKey)).toBe('103');
        expect(await client.get(monthKey)).toBe('503');
        expect(await client.call('EXPIRETIME', weekKey)).toBe(
          getApiKeyCounterExpireAt('week', now),
        );

        // The usage job then saves the combined totals
        await usageService.sync();
        expect(
          prisma.usage.get(`${row.id}|${formatApiKeyUsagePeriod('week', now)}`)
            ?.count,
        ).toBe(103n);
        expect(
          prisma.usage.get(`${row.id}|${formatApiKeyUsagePeriod('month', now)}`)
            ?.count,
        ).toBe(503n);
      });

      it('keep BIGINT totals exact above 2^31 and above 2^53', async () => {
        const { row } = prisma.seedKey();
        const now = nowSeconds();
        const week = formatApiKeyUsagePeriod('week', now);
        const month = formatApiKeyUsagePeriod('month', now);
        prisma.setUsage(row.id, week, 3_000_000_000n);
        prisma.setUsage(row.id, month, 9_007_199_254_740_993n);

        await kongCounts(row.keyHash, 2);
        await index.rebuildIfMissing('redis-ready');

        expect(
          await client.get(buildApiKeyCounterKey(row.keyHash, 'week', now)),
        ).toBe('3000000002');
        expect(
          await client.get(buildApiKeyCounterKey(row.keyHash, 'month', now)),
        ).toBe('9007199254740995');

        await usageService.sync();
        expect(prisma.usage.get(`${row.id}|${week}`)?.count).toBe(
          3_000_000_002n,
        );
        expect(prisma.usage.get(`${row.id}|${month}`)?.count).toBe(
          9_007_199_254_740_995n,
        );
        const usage = await service.usage(row.id);
        expect(usage).toEqual(
          expect.arrayContaining([
            { period: week, count: 3_000_000_002 },
            { period: month, count: '9007199254740995' },
          ]),
        );
      });

      it('seeds a counter that did not exist yet, with the contract expiry', async () => {
        const { row } = prisma.seedKey();
        const now = nowSeconds();
        prisma.setUsage(row.id, formatApiKeyUsagePeriod('month', now), 42n);
        await index.rebuildIfMissing('startup');
        const monthKey = buildApiKeyCounterKey(row.keyHash, 'month', now);
        expect(await client.get(monthKey)).toBe('42');
        expect(await client.call('EXPIRETIME', monthKey)).toBe(
          getApiKeyCounterExpireAt('month', now),
        );
        expect(
          await client.exists(buildApiKeyCounterKey(row.keyHash, 'week', now)),
        ).toBe(0);
      });

      it('adds the saved totals only once when an interrupted rebuild runs again', async () => {
        const { row } = prisma.seedKey();
        const now = nowSeconds();
        prisma.setUsage(row.id, formatApiKeyUsagePeriod('week', now), 100n);

        jest
          .spyOn(index, 'writeMarker')
          .mockRejectedValueOnce(new Error('crashed before the marker'));
        await expect(index.rebuildIfMissing('first')).rejects.toThrow(
          'crashed before the marker',
        );
        expect(await client.exists(API_KEY_INDEX_MARKER_KEY)).toBe(0);
        expect(await client.exists(API_KEY_REBUILD_LOCK_KEY)).toBe(0);

        await index.rebuildIfMissing('second');
        expect(
          await client.get(buildApiKeyCounterKey(row.keyHash, 'week', now)),
        ).toBe('100');
        expect(
          await client.exists(buildApiKeySeedFlagKey(row.keyHash, 'week', now)),
        ).toBe(1);
      });
    });

    describe('Usage sync job', () => {
      it('copies current and previous week and month totals and the last-used time', async () => {
        const { row } = prisma.seedKey();
        await client.set(API_KEY_INDEX_MARKER_KEY, '{}');
        const now = nowSeconds();
        const lastWeek = now - 7 * DAY;
        await client.set(buildApiKeyCounterKey(row.keyHash, 'week', now), '5');
        await client.set(
          buildApiKeyCounterKey(row.keyHash, 'week', lastWeek),
          '9',
        );
        await client.set(
          buildApiKeyCounterKey(row.keyHash, 'month', now),
          '14',
        );
        await client.set(buildApiKeyLastUsedKey(row.keyHash), String(now - 30));
        prisma.setUsage(row.id, formatApiKeyUsagePeriod('month', now), 20n);

        const result = await usageService.sync();

        expect(result).toMatchObject({
          success: true,
          rebuild: 'present',
          keys: 1,
          periodsUpdated: 3,
          lastUsedUpdated: 1,
        });
        const saved = (
          at: number,
          window: 'week' | 'month',
        ): bigint | undefined =>
          prisma.usage.get(`${row.id}|${formatApiKeyUsagePeriod(window, at)}`)
            ?.count;
        expect(saved(now, 'week')).toBe(5n);
        expect(saved(lastWeek, 'week')).toBe(9n);
        // Never lowers a saved total
        expect(saved(now, 'month')).toBe(20n);
        expect(prisma.keys.get(row.id)?.lastUsedAt?.getTime()).toBe(
          (now - 30) * 1000,
        );
      });

      it('rebuilds a missing index first', async () => {
        const { row } = prisma.seedKey();
        const result = await usageService.sync();
        expect(result.rebuild).toBe('rebuilt');
        expect(await record(row.keyHash)).toBe(expectedValue(row));
      });

      it('copies nothing while the index is still missing (rebuild locked elsewhere)', async () => {
        const { row } = prisma.seedKey();
        const now = nowSeconds();
        prisma.setUsage(row.id, formatApiKeyUsagePeriod('week', now), 100n);
        await client.set(API_KEY_REBUILD_LOCK_KEY, 'other', 'PX', 60_000);
        await client.set(buildApiKeyCounterKey(row.keyHash, 'week', now), '2');

        const result = await usageService.sync();

        expect(result).toMatchObject({
          success: false,
          rebuild: 'locked',
          skipped: 'index missing',
        });
        expect(
          prisma.usage.get(`${row.id}|${formatApiKeyUsagePeriod('week', now)}`)
            ?.count,
        ).toBe(100n);
      });
    });

    if (cluster) {
      it('every multi-key call uses one hash slot (CLUSTER KEYSLOT)', async () => {
        const { row } = prisma.seedKey();
        const now = nowSeconds();
        const names = [
          buildApiKeyRecordKey(row.keyHash),
          buildApiKeyCounterKey(row.keyHash, 'week', now),
          buildApiKeySeedFlagKey(row.keyHash, 'week', now),
          buildApiKeyCounterKey(row.keyHash, 'month', now),
          buildApiKeySeedFlagKey(row.keyHash, 'month', now),
          buildApiKeyLastUsedKey(row.keyHash),
          buildApiKeyCounterKey(row.keyHash, 'minute', now),
        ];
        const slots = new Set<unknown>();
        for (const name of names) {
          slots.add(await client.call('CLUSTER', 'KEYSLOT', name));
        }
        expect(slots.size).toBe(1);
        expect(
          await client.call('CLUSTER', 'KEYSLOT', API_KEY_INDEX_MARKER_KEY),
        ).not.toBe([...slots][0]);
      });
    }
  });
}
