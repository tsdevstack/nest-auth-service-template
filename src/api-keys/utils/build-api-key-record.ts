import {
  API_KEY_RECORD_VERSION,
  API_KEY_STATUSES,
} from '@tsdevstack/nest-common';
import type { ApiKeyRecord, ApiKeyRecordLimits } from '@tsdevstack/nest-common';
import { ApiKeyStatus } from '../../generated/prisma/enums';
import type { ApiKeyRecordSource } from '../api-keys.types';
import { toEpochSeconds } from './to-epoch-seconds';

/**
 * Builds the full Redis record of a key from its database row. Records are
 * whole objects; nothing is merged with what Redis holds.
 */
export function buildApiKeyRecord(source: ApiKeyRecordSource): ApiKeyRecord {
  const limits: ApiKeyRecordLimits = {};
  if (source.limitPerMinute !== null) limits.minute = source.limitPerMinute;
  if (source.limitPerHour !== null) limits.hour = source.limitPerHour;
  if (source.limitPerDay !== null) limits.day = source.limitPerDay;
  if (source.limitPerWeek !== null) limits.week = source.limitPerWeek;
  if (source.limitPerMonth !== null) limits.month = source.limitPerMonth;

  const record: ApiKeyRecord = {
    v: API_KEY_RECORD_VERSION,
    id: source.id,
    consumer: source.consumer,
    status:
      source.status === ApiKeyStatus.REVOKED
        ? API_KEY_STATUSES.REVOKED
        : API_KEY_STATUSES.ACTIVE,
    limits,
  };

  if (source.expiresAt !== null) {
    record.expiresAt = toEpochSeconds(source.expiresAt);
  }

  return record;
}
