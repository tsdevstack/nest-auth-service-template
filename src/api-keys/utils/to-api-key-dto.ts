import type { ApiKey } from '../../generated/prisma/client';
import type { ApiKeyDto } from '../dto/api-key.dto';

/**
 * Maps a database row to the admin view: drops the hash and derives
 * `expired` from `expiresAt`.
 */
export function toApiKeyDto(row: ApiKey, now: Date): ApiKeyDto {
  return {
    id: row.id,
    name: row.name,
    prefix: row.prefix,
    consumer: row.consumer,
    limitPerMinute: row.limitPerMinute,
    limitPerHour: row.limitPerHour,
    limitPerDay: row.limitPerDay,
    limitPerWeek: row.limitPerWeek,
    limitPerMonth: row.limitPerMonth,
    status: row.status,
    expired: row.expiresAt !== null && row.expiresAt.getTime() <= now.getTime(),
    expiresAt: row.expiresAt,
    lastUsedAt: row.lastUsedAt,
    revokedAt: row.revokedAt,
    createdById: row.createdById,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}
