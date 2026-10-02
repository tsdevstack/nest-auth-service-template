import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { LoggerService } from '@tsdevstack/nest-common';
import { PrismaService } from '../prisma/prisma.service';
import { ApiKeyStatus } from '../generated/prisma/enums';
import type { ApiKey } from '../generated/prisma/client';
import { ApiKeyIndexService } from './api-key-index.service';
import { API_KEY_ROTATION_DEFAULT_GRACE_HOURS } from './api-keys.constants';
import type { ApiKeyRecordState, ApiKeyRecordWrite } from './api-keys.types';
import type { ApiKeyDto } from './dto/api-key.dto';
import type { ApiKeyUsageDto } from './dto/api-key-usage.dto';
import type { CreateApiKeyDto } from './dto/create-api-key.dto';
import type { CreatedApiKeyDto } from './dto/created-api-key.dto';
import type { RotatedApiKeyDto } from './dto/rotated-api-key.dto';
import type { UpdateApiKeyDto } from './dto/update-api-key.dto';
import { generateApiKey } from './utils/generate-api-key';
import { parseApiKeyExpiry } from './utils/parse-api-key-expiry';
import { resolveApiKeyRecordState } from './utils/resolve-api-key-record-state';
import { toApiKeyDto } from './utils/to-api-key-dto';
import { toApiKeyUsageCount } from './utils/to-api-key-usage-count';
import { toEpochSeconds } from './utils/to-epoch-seconds';

const HOUR_MS = 3_600_000;

const CHANGED_MEANWHILE =
  'The API key changed while this request ran; reload it and retry';

/** A Redis write and the row whose database state repairs it */
interface PendingWrite {
  write: ApiKeyRecordWrite;
  id: string;
}

/**
 * Admin management of API keys.
 *
 * Every change writes the key's full Redis record first, then Postgres:
 *
 * - Redis fails: the operation fails (503) and nothing changed.
 * - Postgres writes are conditional on the row being unchanged since it was
 *   read (`updatedAt`, and `status: ACTIVE` for changes of active keys), so
 *   two admin operations on one key cannot both commit from the same
 *   snapshot. A lost race is a 409.
 * - Postgres fails or the condition does not match: each Redis write is
 *   repaired from the database (re-read the row, write its record only while
 *   Redis still holds our value), then the error is rethrown.
 *
 * A key's plaintext is only returned when the whole operation succeeded.
 *
 * Remaining residual: if the re-read also fails, the repair falls back to
 * restoring the previous Redis value (a revoked record written by us is kept
 * instead). That restore can be wrong in two cases, until the admin repeats
 * the operation: Postgres committed although it reported an error (the old
 * record comes back), or a rebuild ran between our write and the failure
 * while the previous state was "no record" (the key loses its record and
 * gets 401). If the Redis repair itself fails, Redis and Postgres differ
 * until the operation is repeated.
 */
@Injectable()
export class ApiKeysService {
  private readonly logger: LoggerService;

  constructor(
    private readonly prisma: PrismaService,
    private readonly index: ApiKeyIndexService,
    logger: LoggerService,
  ) {
    this.logger = logger.child('ApiKeysService');
  }

  async list(consumer?: string): Promise<ApiKeyDto[]> {
    const rows = await this.prisma.apiKey.findMany({
      where: consumer ? { consumer } : {},
      orderBy: { createdAt: 'desc' },
    });
    const now = new Date();
    return rows.map((row) => toApiKeyDto(row, now));
  }

  async get(id: string): Promise<ApiKeyDto> {
    return toApiKeyDto(await this.findOrThrow(id), new Date());
  }

  async usage(id: string): Promise<ApiKeyUsageDto[]> {
    await this.findOrThrow(id);
    const rows = await this.prisma.apiKeyUsage.findMany({
      where: { keyId: id },
      orderBy: { period: 'desc' },
    });
    return rows.map(({ period, count }) => ({
      period,
      count: toApiKeyUsageCount(count),
    }));
  }

  async create(
    adminId: string,
    dto: CreateApiKeyDto,
  ): Promise<CreatedApiKeyDto> {
    const now = new Date();
    const expiresAt = parseApiKeyExpiry(dto.expiresAt);
    if (expiresAt !== null && expiresAt.getTime() <= now.getTime()) {
      throw new BadRequestException('expiresAt must be in the future');
    }

    const generated = generateApiKey();
    const data = {
      id: randomUUID(),
      name: dto.name,
      prefix: generated.prefix,
      keyHash: generated.keyHash,
      consumer: dto.consumer,
      createdById: adminId,
      limitPerMinute: dto.limitPerMinute ?? null,
      limitPerHour: dto.limitPerHour ?? null,
      limitPerDay: dto.limitPerDay ?? null,
      limitPerWeek: dto.limitPerWeek ?? null,
      limitPerMonth: dto.limitPerMonth ?? null,
      status: ApiKeyStatus.ACTIVE,
      expiresAt,
      revokedAt: null,
    };

    const write = await this.writeRedis(
      generated.keyHash,
      resolveApiKeyRecordState(data, toEpochSeconds(now)),
    );
    const row = await this.writePostgres([{ write, id: data.id }], () =>
      this.prisma.apiKey.create({ data }),
    );

    this.logger.info('API key created', {
      keyId: row.id,
      consumer: row.consumer,
      adminId,
    });
    return { ...toApiKeyDto(row, now), key: generated.key };
  }

  async update(id: string, dto: UpdateApiKeyDto): Promise<ApiKeyDto> {
    const current = await this.findOrThrow(id);
    if (current.status === ApiKeyStatus.REVOKED) {
      throw new ConflictException('A revoked key cannot be changed');
    }

    const changes = {
      ...(dto.name !== undefined && { name: dto.name }),
      ...(dto.limitPerMinute !== undefined && {
        limitPerMinute: dto.limitPerMinute,
      }),
      ...(dto.limitPerHour !== undefined && { limitPerHour: dto.limitPerHour }),
      ...(dto.limitPerDay !== undefined && { limitPerDay: dto.limitPerDay }),
      ...(dto.limitPerWeek !== undefined && { limitPerWeek: dto.limitPerWeek }),
      ...(dto.limitPerMonth !== undefined && {
        limitPerMonth: dto.limitPerMonth,
      }),
      ...(dto.expiresAt !== undefined && {
        expiresAt: parseApiKeyExpiry(dto.expiresAt),
      }),
    };

    const now = new Date();
    const write = await this.writeRedis(
      current.keyHash,
      resolveApiKeyRecordState({ ...current, ...changes }, toEpochSeconds(now)),
    );
    const row = await this.writePostgres([{ write, id }], () =>
      this.prisma.$transaction(async (tx) => {
        const { count } = await tx.apiKey.updateMany({
          where: this.unchangedSince(current),
          data: { ...changes, updatedAt: this.nextUpdatedAt(current, now) },
        });
        if (count === 0) throw new ConflictException(CHANGED_MEANWHILE);
        return await tx.apiKey.findUniqueOrThrow({ where: { id } });
      }),
    );

    this.logger.info('API key updated', { keyId: id, consumer: row.consumer });
    return toApiKeyDto(row, now);
  }

  /**
   * Revokes a key. Revoking a revoked key changes nothing in Postgres but
   * rewrites its revoked record (the repair path when an earlier revoke left
   * Redis behind); the record still expires one day after `revokedAt`.
   */
  async revoke(id: string): Promise<ApiKeyDto> {
    const current = await this.findOrThrow(id);
    const now = new Date();
    if (current.status === ApiKeyStatus.REVOKED) {
      await this.writeRedis(
        current.keyHash,
        resolveApiKeyRecordState(current, toEpochSeconds(now)),
      );
      return toApiKeyDto(current, now);
    }

    const write = await this.writeRedis(
      current.keyHash,
      resolveApiKeyRecordState(
        { ...current, status: ApiKeyStatus.REVOKED, revokedAt: now },
        toEpochSeconds(now),
      ),
    );
    const row = await this.writePostgres([{ write, id }], () =>
      this.prisma.$transaction(async (tx) => {
        const { count } = await tx.apiKey.updateMany({
          where: this.unchangedSince(current),
          data: {
            status: ApiKeyStatus.REVOKED,
            revokedAt: now,
            updatedAt: this.nextUpdatedAt(current, now),
          },
        });
        if (count === 0) throw new ConflictException(CHANGED_MEANWHILE);
        return await tx.apiKey.findUniqueOrThrow({ where: { id } });
      }),
    );

    this.logger.info('API key revoked', { keyId: id, consumer: row.consumer });
    return toApiKeyDto(row, now);
  }

  /**
   * Issues a replacement key with the same name, consumer, limits and expiry,
   * and shortens the old key's expiry to the earlier of its current expiry
   * and now plus the grace. Both keys work during the grace.
   */
  async rotate(
    adminId: string,
    id: string,
    graceHours: number = API_KEY_ROTATION_DEFAULT_GRACE_HOURS,
  ): Promise<RotatedApiKeyDto> {
    const current = await this.findOrThrow(id);
    const now = new Date();
    if (current.status === ApiKeyStatus.REVOKED) {
      throw new ConflictException('A revoked key cannot be rotated');
    }
    if (
      current.expiresAt !== null &&
      current.expiresAt.getTime() <= now.getTime()
    ) {
      throw new ConflictException(
        'An expired key cannot be rotated; extend its expiry first',
      );
    }

    const graceEnd = new Date(now.getTime() + graceHours * HOUR_MS);
    const previousExpiresAt =
      current.expiresAt !== null && current.expiresAt < graceEnd
        ? current.expiresAt
        : graceEnd;

    const generated = generateApiKey();
    const data = {
      id: randomUUID(),
      name: current.name,
      prefix: generated.prefix,
      keyHash: generated.keyHash,
      consumer: current.consumer,
      createdById: adminId,
      limitPerMinute: current.limitPerMinute,
      limitPerHour: current.limitPerHour,
      limitPerDay: current.limitPerDay,
      limitPerWeek: current.limitPerWeek,
      limitPerMonth: current.limitPerMonth,
      status: ApiKeyStatus.ACTIVE,
      expiresAt: current.expiresAt,
      revokedAt: null,
    };
    const nowSeconds = toEpochSeconds(now);

    const newWrite = await this.writeRedis(
      generated.keyHash,
      resolveApiKeyRecordState(data, nowSeconds),
    );
    let oldWrite: ApiKeyRecordWrite;
    try {
      oldWrite = await this.writeRedis(
        current.keyHash,
        resolveApiKeyRecordState(
          { ...current, expiresAt: previousExpiresAt },
          nowSeconds,
        ),
      );
    } catch (error) {
      await this.repair([{ write: newWrite, id: data.id }]);
      throw error;
    }

    const [created, previous] = await this.writePostgres(
      [
        { write: oldWrite, id },
        { write: newWrite, id: data.id },
      ],
      () =>
        this.prisma.$transaction(async (tx) => {
          const { count } = await tx.apiKey.updateMany({
            where: this.unchangedSince(current),
            data: {
              expiresAt: previousExpiresAt,
              updatedAt: this.nextUpdatedAt(current, now),
            },
          });
          if (count === 0) throw new ConflictException(CHANGED_MEANWHILE);
          const fresh = await tx.apiKey.create({ data });
          const old = await tx.apiKey.findUniqueOrThrow({ where: { id } });
          return [fresh, old] as const;
        }),
    );

    this.logger.info('API key rotated', {
      keyId: id,
      newKeyId: created.id,
      consumer: created.consumer,
      adminId,
    });
    return {
      newKey: { ...toApiKeyDto(created, now), key: generated.key },
      previousKey: toApiKeyDto(previous, now),
    };
  }

  private async findOrThrow(id: string): Promise<ApiKey> {
    const row = await this.prisma.apiKey.findUnique({ where: { id } });
    if (!row) {
      throw new NotFoundException('API key not found');
    }
    return row;
  }

  /** Row condition: still active and not changed since `current` was read */
  private unchangedSince(current: ApiKey): {
    id: string;
    status: ApiKeyStatus;
    updatedAt: Date;
  } {
    return {
      id: current.id,
      status: ApiKeyStatus.ACTIVE,
      updatedAt: current.updatedAt,
    };
  }

  /**
   * New `updatedAt`, strictly after the one read, so a write in the same
   * millisecond as the previous one still changes the version.
   */
  private nextUpdatedAt(current: ApiKey, now: Date): Date {
    return new Date(Math.max(now.getTime(), current.updatedAt.getTime() + 1));
  }

  /** Redis first: a failure here leaves everything unchanged */
  private async writeRedis(
    keyHash: string,
    state: ApiKeyRecordState,
  ): Promise<ApiKeyRecordWrite> {
    try {
      return await this.index.writeRecord(keyHash, state);
    } catch (error) {
      this.logger.error('API key index write failed; nothing changed', error);
      throw new ServiceUnavailableException(
        'API key index (Redis) unavailable; nothing was changed',
      );
    }
  }

  /**
   * Postgres second: on any failure (including a lost race, 409) the Redis
   * writes are repaired from the database, last write first.
   */
  private async writePostgres<T>(
    writes: PendingWrite[],
    operation: () => Promise<T>,
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      await this.repair(writes);
      throw error;
    }
  }

  private async repair(writes: PendingWrite[]): Promise<void> {
    for (const { write, id } of writes) {
      await this.index.repairRecordWrite(write, async () => {
        const row = await this.prisma.apiKey.findUnique({ where: { id } });
        return row
          ? resolveApiKeyRecordState(row, toEpochSeconds(new Date()))
          : null;
      });
    }
  }
}
