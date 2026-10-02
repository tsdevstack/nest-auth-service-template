import { randomBytes } from 'node:crypto';
import { hashApiKey } from '@tsdevstack/nest-common';
import type { ApiKey, ApiKeyUsage } from '../../src/generated/prisma/client';

/**
 * Injectable Postgres failures, consumed in order of occurrence:
 * - `create`, `findUnique`: that call throws
 * - `transaction`: the interactive transaction throws before running
 * - `commit-then-fail`: the transaction commits, then reports an error
 *   (an ambiguous failure, for example a lost connection during COMMIT)
 */
export type FakePrismaFailure =
  'create' | 'findUnique' | 'transaction' | 'commit-then-fail';

interface UpdateManyWhere {
  id: string;
  status?: ApiKey['status'];
  updatedAt?: Date;
}

/**
 * In-memory stand-in for the Prisma calls the API key services make, with
 * the semantics they rely on: `updateMany` matches `id`, `status` and
 * `updatedAt` exactly and returns the number of rows changed; `@updatedAt`
 * is set when the data does not set it; an interactive `$transaction` rolls
 * everything back when its callback throws.
 */
export class FakeApiKeyPrisma {
  keys = new Map<string, ApiKey>();
  usage = new Map<string, ApiKeyUsage>();
  failures: FakePrismaFailure[] = [];
  /** Committed row writes (create and matching updateMany) */
  writes = 0;

  apiKey = {
    findUnique: ({
      where,
    }: {
      where: { id: string };
    }): Promise<ApiKey | null> => {
      if (this.consume('findUnique')) {
        return Promise.reject(new Error('simulated Postgres failure (read)'));
      }
      return Promise.resolve(this.keys.get(where.id) ?? null);
    },

    findUniqueOrThrow: ({
      where,
    }: {
      where: { id: string };
    }): Promise<ApiKey> => {
      const row = this.keys.get(where.id);
      return row
        ? Promise.resolve(row)
        : Promise.reject(new Error('No record found'));
    },

    findMany: (args: {
      where?: Record<string, unknown>;
      include?: { usage: { where: { period: { in: string[] } } } };
      take?: number;
    }): Promise<unknown[]> => {
      const where = args.where ?? {};
      const idGt = (where.id as { gt?: string } | undefined)?.gt;
      const status = where.status as string | undefined;
      const expiryOr = where.OR as
        { expiresAt: null | { gt: Date } }[] | undefined;
      const gt = expiryOr?.find((c) => c.expiresAt !== null)?.expiresAt as
        { gt: Date } | undefined;
      const rows = [...this.keys.values()]
        .filter((row) => (idGt ? row.id > idGt : true))
        .filter((row) => (status ? row.status === status : true))
        .filter(
          (row) =>
            !expiryOr ||
            row.expiresAt === null ||
            (gt ? row.expiresAt > gt.gt : true),
        )
        // The usage sync's AND filter (recently revoked or expired) is not
        // modelled: every key in these tests is recent
        .sort((a, b) => (a.id < b.id ? -1 : 1))
        .slice(0, args.take ?? Infinity);
      const periods = args.include?.usage.where.period.in;
      return Promise.resolve(
        rows.map((row) =>
          periods
            ? {
                ...row,
                usage: [...this.usage.values()].filter(
                  (u) => u.keyId === row.id && periods.includes(u.period),
                ),
              }
            : row,
        ),
      );
    },

    create: ({
      data,
    }: {
      data: Partial<ApiKey> & { id: string };
    }): Promise<ApiKey> => {
      if (this.consume('create')) {
        return Promise.reject(new Error('simulated Postgres failure (create)'));
      }
      if (this.keys.has(data.id)) {
        return Promise.reject(new Error('Unique constraint failed on id'));
      }
      const now = new Date();
      const row = {
        lastUsedAt: null,
        revokedAt: null,
        createdAt: now,
        updatedAt: now,
        ...data,
      } as ApiKey;
      this.keys.set(row.id, row);
      this.writes += 1;
      return Promise.resolve(row);
    },

    updateMany: ({
      where,
      data,
    }: {
      where: UpdateManyWhere;
      data: Partial<ApiKey>;
    }): Promise<{ count: number }> => {
      const row = this.keys.get(where.id);
      const matches =
        row !== undefined &&
        (where.status === undefined || row.status === where.status) &&
        (where.updatedAt === undefined ||
          row.updatedAt.getTime() === where.updatedAt.getTime());
      if (!matches) {
        return Promise.resolve({ count: 0 });
      }
      this.keys.set(row.id, { ...row, updatedAt: new Date(), ...data });
      this.writes += 1;
      return Promise.resolve({ count: 1 });
    },
  };

  apiKeyUsage = {
    findMany: ({
      where,
    }: {
      where: { keyId: string };
    }): Promise<ApiKeyUsage[]> =>
      Promise.resolve(
        [...this.usage.values()]
          .filter((u) => u.keyId === where.keyId)
          .sort((a, b) => (a.period < b.period ? 1 : -1)),
      ),
  };

  $transaction = async <T>(
    callback: (tx: FakeApiKeyPrisma) => Promise<T>,
  ): Promise<T> => {
    if (this.consume('transaction')) {
      throw new Error('simulated Postgres failure (transaction)');
    }
    const keys = new Map(this.keys);
    const writes = this.writes;
    let result: T;
    try {
      result = await callback(this);
    } catch (error) {
      this.keys = keys;
      this.writes = writes;
      throw error;
    }
    if (this.consume('commit-then-fail')) {
      throw new Error('simulated Postgres failure after commit');
    }
    return result;
  };

  $executeRaw = (
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<number> => {
    const sql = strings.join('?');
    if (sql.includes('INSERT INTO "ApiKeyUsage"')) {
      const [keyId, period, count] = values as [string, string, bigint];
      if (typeof count !== 'bigint') {
        return Promise.reject(new Error('count must be a bigint (BIGINT)'));
      }
      const id = `${keyId}|${period}`;
      const existing = this.usage.get(id)?.count ?? 0n;
      this.usage.set(id, {
        keyId,
        period,
        count: existing > count ? existing : count,
      });
      return Promise.resolve(1);
    }
    if (sql.includes('UPDATE "ApiKey" SET "lastUsedAt"')) {
      const [lastUsedAt, id] = values as [Date, string];
      const row = this.keys.get(id);
      if (row && (row.lastUsedAt === null || row.lastUsedAt < lastUsedAt)) {
        this.keys.set(id, { ...row, lastUsedAt });
        return Promise.resolve(1);
      }
      return Promise.resolve(0);
    }
    return Promise.reject(new Error(`unexpected SQL: ${sql}`));
  };

  /** Adds an active key directly (no Redis write) */
  seedKey(overrides: Partial<ApiKey> = {}): { row: ApiKey; key: string } {
    const key = `tsk_${randomBytes(32).toString('base64url')}`;
    const now = new Date();
    const row: ApiKey = {
      id: `seed-${randomBytes(4).toString('hex')}`,
      name: 'seeded',
      prefix: key.slice(0, 12),
      keyHash: hashApiKey(key),
      consumer: 'acme-corp',
      createdById: 'admin-1',
      limitPerMinute: 10,
      limitPerHour: null,
      limitPerDay: null,
      limitPerWeek: null,
      limitPerMonth: null,
      status: 'ACTIVE',
      expiresAt: null,
      lastUsedAt: null,
      revokedAt: null,
      createdAt: now,
      updatedAt: now,
      ...overrides,
    };
    this.keys.set(row.id, row);
    return { row, key };
  }

  setUsage(keyId: string, period: string, count: bigint): void {
    this.usage.set(`${keyId}|${period}`, { keyId, period, count });
  }

  private consume(failure: FakePrismaFailure): boolean {
    const index = this.failures.indexOf(failure);
    if (index === -1) return false;
    this.failures.splice(index, 1);
    return true;
  }
}
