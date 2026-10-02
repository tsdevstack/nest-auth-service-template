import {
  BadRequestException,
  ConflictException,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { LoggerService } from '@tsdevstack/nest-common';
import { decodeApiKeyRecord, hashApiKey } from '@tsdevstack/nest-common';
import type { ApiKey } from '../generated/prisma/client';
import type { PrismaService } from '../prisma/prisma.service';
import type { ApiKeyIndexService } from './api-key-index.service';
import { ApiKeysService } from './api-keys.service';
import type { ApiKeyRecordState, ApiKeyRecordWrite } from './api-keys.types';
import { FakeApiKeyPrisma } from '../../test/support/fake-api-key-prisma';

describe('ApiKeysService', () => {
  const now = Date.now();

  let prisma: FakeApiKeyPrisma;
  let row: ApiKey;
  let index: { writeRecord: jest.Mock; repairRecordWrite: jest.Mock };
  let service: ApiKeysService;

  /** Record states written to Redis, in order */
  const writtenStates = (): { value: string; expireAt: number | null }[] =>
    index.writeRecord.mock.calls.map(
      (call: unknown[]) =>
        call[1] as { value: string; expireAt: number | null },
    );

  /** Record states the repairs resolved from the database, in order */
  const repairs = async (): Promise<
    { key: string; truth: ApiKeyRecordState }[]
  > => {
    const calls = index.repairRecordWrite.mock.calls as [
      ApiKeyRecordWrite,
      () => Promise<ApiKeyRecordState>,
    ][];
    const result: { key: string; truth: ApiKeyRecordState }[] = [];
    for (const [write, loadTruth] of calls) {
      result.push({ key: write.key, truth: await loadTruth() });
    }
    return result;
  };

  beforeEach(() => {
    prisma = new FakeApiKeyPrisma();
    row = prisma.seedKey({
      id: 'k1',
      name: 'Integration',
      createdAt: new Date(now - 60_000),
      updatedAt: new Date(now - 60_000),
    }).row;
    index = {
      writeRecord: jest.fn((key: string, state: ApiKeyRecordState) =>
        Promise.resolve({
          key,
          written: state?.value ?? null,
          previous: null,
          previousExpireAtMs: null,
        }),
      ),
      repairRecordWrite: jest.fn().mockResolvedValue(true),
    };
    const logger = {
      child: () => logger,
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };
    service = new ApiKeysService(
      prisma as unknown as PrismaService,
      index as unknown as ApiKeyIndexService,
      logger as unknown as LoggerService,
    );
  });

  describe('list, get and usage', () => {
    it('lists newest first, optionally by consumer, deriving expired', async () => {
      prisma.keys.set('k1', { ...row, expiresAt: new Date(now - 1000) });
      const findMany = jest.spyOn(prisma.apiKey, 'findMany');
      const [dto] = await service.list('acme-corp');
      expect(findMany).toHaveBeenCalledWith({
        where: { consumer: 'acme-corp' },
        orderBy: { createdAt: 'desc' },
      });
      expect(dto.expired).toBe(true);
      expect(dto).not.toHaveProperty('keyHash');
    });

    it('lists every key without a filter', async () => {
      const findMany = jest.spyOn(prisma.apiKey, 'findMany');
      await service.list();
      expect(findMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: {} }),
      );
    });

    it('returns 404 for an unknown key', async () => {
      await expect(service.get('nope')).rejects.toBeInstanceOf(
        NotFoundException,
      );
      await expect(service.usage('nope')).rejects.toBeInstanceOf(
        NotFoundException,
      );
    });

    it('returns saved usage periods newest first, BIGINT serialized exactly', async () => {
      prisma.setUsage('k1', '2026-W40', 3n);
      prisma.setUsage('k1', '2026-10', 9_007_199_254_740_993n);
      await expect(service.usage('k1')).resolves.toEqual([
        { period: '2026-W40', count: 3 },
        { period: '2026-10', count: '9007199254740993' },
      ]);
    });
  });

  describe('create', () => {
    it('writes Redis before Postgres and returns the key once', async () => {
      const order: string[] = [];
      index.writeRecord.mockImplementationOnce(
        (key: string, state: ApiKeyRecordState) => {
          order.push('redis');
          return Promise.resolve({
            key,
            written: state?.value ?? null,
            previous: null,
            previousExpireAtMs: null,
          });
        },
      );
      const create = prisma.apiKey.create;
      jest
        .spyOn(prisma.apiKey, 'create')
        .mockImplementationOnce((args: Parameters<typeof create>[0]) => {
          order.push('postgres');
          return create(args);
        });

      const created = await service.create('admin-9', {
        name: 'n',
        consumer: 'new-co',
        limitPerHour: 5,
      });

      expect(order).toEqual(['redis', 'postgres']);
      expect(created.key).toMatch(/^tsk_/);
      const [hash] = index.writeRecord.mock.calls[0] as [string];
      expect(hash).toBe(hashApiKey(created.key));
      expect(decodeApiKeyRecord(writtenStates()[0].value)).toEqual({
        v: 1,
        id: created.id,
        consumer: 'new-co',
        status: 'active',
        limits: { hour: 5 },
      });
      const saved = prisma.keys.get(created.id);
      expect(saved).toMatchObject({ createdById: 'admin-9', keyHash: hash });
      expect(JSON.stringify(saved)).not.toContain(created.key);
    });

    it('rejects an expiry that is not in the future before any write', async () => {
      await expect(
        service.create('admin-1', {
          name: 'n',
          consumer: 'acme-corp',
          expiresAt: new Date(now - 1000).toISOString(),
        }),
      ).rejects.toBeInstanceOf(BadRequestException);
      expect(index.writeRecord).not.toHaveBeenCalled();
    });

    it('fails with 503 and leaves Postgres alone when Redis fails', async () => {
      index.writeRecord.mockRejectedValue(new Error('Connection is closed.'));
      await expect(
        service.create('admin-1', { name: 'n', consumer: 'acme-corp' }),
      ).rejects.toBeInstanceOf(ServiceUnavailableException);
      expect(prisma.writes).toBe(0);
    });

    it('repairs the Redis write from the database and rethrows when Postgres fails', async () => {
      prisma.failures.push('create');
      await expect(
        service.create('admin-1', { name: 'n', consumer: 'acme-corp' }),
      ).rejects.toThrow('simulated Postgres failure (create)');
      // The row does not exist, so the repair deletes the record
      expect(await repairs()).toEqual([
        { key: expect.any(String) as string, truth: null },
      ]);
    });
  });

  describe('update', () => {
    it('keeps absent fields and clears null ones', async () => {
      const updated = await service.update('k1', {
        limitPerMinute: null,
        limitPerDay: 9,
      });
      expect(updated).toMatchObject({
        name: 'Integration',
        limitPerMinute: null,
        limitPerDay: 9,
      });
      expect(decodeApiKeyRecord(writtenStates()[0].value).limits).toEqual({
        day: 9,
      });
    });

    it('sets and clears the expiry', async () => {
      const at = new Date(now + 3_600_000).toISOString();
      await service.update('k1', { expiresAt: at });
      expect(prisma.keys.get('k1')?.expiresAt).toEqual(new Date(at));
      await service.update('k1', { expiresAt: null });
      expect(prisma.keys.get('k1')?.expiresAt).toBeNull();
    });

    it('moves updatedAt forward even within the same millisecond', async () => {
      prisma.keys.set('k1', { ...row, updatedAt: new Date(now + 60_000) });
      await service.update('k1', { name: 'x' });
      expect(prisma.keys.get('k1')?.updatedAt.getTime()).toBe(now + 60_001);
    });

    it('refuses to change a revoked key', async () => {
      prisma.keys.set('k1', { ...row, status: 'REVOKED' });
      await expect(service.update('k1', { name: 'x' })).rejects.toBeInstanceOf(
        ConflictException,
      );
      expect(index.writeRecord).not.toHaveBeenCalled();
    });

    it('is a 409 when the row changed after it was read, and repairs Redis', async () => {
      index.writeRecord.mockImplementationOnce(
        (key: string, state: ApiKeyRecordState) => {
          prisma.keys.set('k1', {
            ...row,
            limitPerHour: 5,
            updatedAt: new Date(now),
          });
          return Promise.resolve({
            key,
            written: state?.value ?? null,
            previous: null,
            previousExpireAtMs: null,
          });
        },
      );
      await expect(
        service.update('k1', { limitPerMinute: 99 }),
      ).rejects.toBeInstanceOf(ConflictException);
      expect(prisma.keys.get('k1')).toMatchObject({
        limitPerMinute: 10,
        limitPerHour: 5,
      });
      const [repair] = await repairs();
      expect(decodeApiKeyRecord(repair.truth?.value as string).limits).toEqual({
        minute: 10,
        hour: 5,
      });
    });

    it('repairs the Redis write when Postgres fails', async () => {
      prisma.failures.push('transaction');
      await expect(service.update('k1', { name: 'x' })).rejects.toThrow(
        'simulated Postgres failure (transaction)',
      );
      expect(index.repairRecordWrite).toHaveBeenCalledTimes(1);
      expect(prisma.keys.get('k1')?.name).toBe('Integration');
    });
  });

  describe('revoke', () => {
    it('writes a revoked record, then marks the row revoked', async () => {
      const dto = await service.revoke('k1');
      const [state] = writtenStates();
      expect(decodeApiKeyRecord(state.value).status).toBe('revoked');
      expect(state.expireAt).toBeGreaterThanOrEqual(
        Math.floor(now / 1000) + 86_400,
      );
      expect(dto.status).toBe('REVOKED');
      expect(prisma.keys.get('k1')?.status).toBe('REVOKED');
      expect(prisma.keys.get('k1')?.revokedAt).toBeInstanceOf(Date);
    });

    it('rewrites the revoked record of a revoked key without touching Postgres', async () => {
      const revokedAt = new Date(now - 3_600_000);
      prisma.keys.set('k1', { ...row, status: 'REVOKED', revokedAt });
      await expect(service.revoke('k1')).resolves.toMatchObject({
        status: 'REVOKED',
      });
      const [state] = writtenStates();
      expect(decodeApiKeyRecord(state.value).status).toBe('revoked');
      // Still one day after the original revokedAt, not extended
      expect(state.expireAt).toBe(
        Math.floor(revokedAt.getTime() / 1000) + 86_400,
      );
      expect(prisma.writes).toBe(0);
    });

    it('is a 409 when another revoke committed first', async () => {
      index.writeRecord.mockImplementationOnce(
        (key: string, state: ApiKeyRecordState) => {
          prisma.keys.set('k1', {
            ...row,
            status: 'REVOKED',
            revokedAt: new Date(now),
            updatedAt: new Date(now),
          });
          return Promise.resolve({
            key,
            written: state?.value ?? null,
            previous: null,
            previousExpireAtMs: null,
          });
        },
      );
      await expect(service.revoke('k1')).rejects.toBeInstanceOf(
        ConflictException,
      );
      const [repair] = await repairs();
      expect(decodeApiKeyRecord(repair.truth?.value as string).status).toBe(
        'revoked',
      );
    });
  });

  describe('rotate', () => {
    it('copies the settings to a new key and shortens the old expiry', async () => {
      const result = await service.rotate('admin-2', 'k1', 24);

      expect(result.newKey.key).toMatch(/^tsk_/);
      expect(result.newKey).toMatchObject({
        name: 'Integration',
        consumer: 'acme-corp',
        limitPerMinute: 10,
        expiresAt: null,
        createdById: 'admin-2',
      });
      const oldExpiry = result.previousKey.expiresAt as Date;
      expect(oldExpiry.getTime()).toBeGreaterThanOrEqual(now + 24 * 3_600_000);
      expect(oldExpiry.getTime()).toBeLessThan(now + 24 * 3_600_000 + 60_000);
      expect(index.writeRecord).toHaveBeenCalledTimes(2);
      expect(prisma.keys.size).toBe(2);
    });

    it('keeps an earlier existing expiry', async () => {
      const soon = new Date(now + 3_600_000);
      prisma.keys.set('k1', { ...row, expiresAt: soon });
      const result = await service.rotate('admin-1', 'k1', 48);
      expect(result.previousKey.expiresAt).toEqual(soon);
      expect(result.newKey.expiresAt).toEqual(soon);
    });

    it('uses a 7-day grace by default and 0 ends the old key now', async () => {
      const weekly = await service.rotate('admin-1', 'k1');
      expect(
        (weekly.previousKey.expiresAt as Date).getTime(),
      ).toBeGreaterThanOrEqual(now + 7 * 24 * 3_600_000);
      const immediate = await service.rotate('admin-1', 'k1', 0);
      expect((immediate.previousKey.expiresAt as Date).getTime()).toBeLessThan(
        now + 60_000,
      );
    });

    it('refuses revoked and expired keys', async () => {
      prisma.keys.set('k1', { ...row, status: 'REVOKED' });
      await expect(service.rotate('a', 'k1')).rejects.toBeInstanceOf(
        ConflictException,
      );
      prisma.keys.set('k1', { ...row, expiresAt: new Date(now - 1000) });
      await expect(service.rotate('a', 'k1')).rejects.toBeInstanceOf(
        ConflictException,
      );
      expect(index.writeRecord).not.toHaveBeenCalled();
    });

    it('repairs both writes, old key first, when Postgres fails', async () => {
      prisma.failures.push('transaction');
      await expect(service.rotate('admin-1', 'k1')).rejects.toThrow(
        'simulated Postgres failure (transaction)',
      );
      const repaired = await repairs();
      expect(repaired.map(({ key }) => key)[0]).toBe(row.keyHash);
      expect(repaired).toHaveLength(2);
      // Old key: back to its database state; new key: no row, no record
      expect(
        decodeApiKeyRecord(repaired[0].truth?.value as string),
      ).not.toHaveProperty('expiresAt');
      expect(repaired[1].truth).toBeNull();
      expect(prisma.keys.size).toBe(1);
    });

    it('is a 409 and creates nothing when the old key changed meanwhile', async () => {
      index.writeRecord.mockImplementationOnce(
        (key: string, state: ApiKeyRecordState) => {
          prisma.keys.set('k1', { ...row, updatedAt: new Date(now) });
          return Promise.resolve({
            key,
            written: state?.value ?? null,
            previous: null,
            previousExpireAtMs: null,
          });
        },
      );
      await expect(service.rotate('admin-1', 'k1')).rejects.toBeInstanceOf(
        ConflictException,
      );
      expect(prisma.keys.size).toBe(1);
      expect(index.repairRecordWrite).toHaveBeenCalledTimes(2);
    });

    it('repairs the new key when the old key write fails', async () => {
      index.writeRecord
        .mockImplementationOnce((key: string) =>
          Promise.resolve({
            key,
            written: 'x',
            previous: null,
            previousExpireAtMs: null,
          }),
        )
        .mockRejectedValueOnce(new Error('Connection is closed.'));
      await expect(service.rotate('admin-1', 'k1')).rejects.toBeInstanceOf(
        ServiceUnavailableException,
      );
      expect(index.repairRecordWrite).toHaveBeenCalledTimes(1);
      expect(prisma.writes).toBe(0);
    });
  });
});
