import {
  encodeApiKeyRecord,
  getApiKeyRecordExpireAt,
} from '@tsdevstack/nest-common';
import { ApiKeyStatus } from '../../generated/prisma/enums';
import type { ApiKeyRecordSource, ApiKeyRecordState } from '../api-keys.types';
import { buildApiKeyRecord } from './build-api-key-record';
import { toEpochSeconds } from './to-epoch-seconds';

/**
 * What a key's Redis record entry should be at `nowSeconds`: the encoded
 * record with its expiry (contract TTL rules), or null when the entry should
 * not exist (expired or revoked longer ago than the retention period).
 *
 * A revoked key keeps its record one day from `revokedAt` (from `nowSeconds`
 * when the row has no `revokedAt` yet), so rewriting it later, for example
 * as a repair, never extends that day.
 */
export function resolveApiKeyRecordState(
  source: ApiKeyRecordSource,
  nowSeconds: number,
): ApiKeyRecordState {
  const record = buildApiKeyRecord(source);
  const referenceSeconds =
    source.status === ApiKeyStatus.REVOKED && source.revokedAt !== null
      ? toEpochSeconds(source.revokedAt)
      : nowSeconds;
  const expireAt = getApiKeyRecordExpireAt(record, referenceSeconds);

  if (expireAt !== null && expireAt <= nowSeconds) {
    return null;
  }

  return { value: encodeApiKeyRecord(record), expireAt };
}
