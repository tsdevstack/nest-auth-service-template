import { resolveApiKeyRecordState } from './resolve-api-key-record-state';
import type { ApiKeyRecordSource } from '../api-keys.types';

const NOW = 1790709764;
const source: ApiKeyRecordSource = {
  id: 'k1',
  consumer: 'acme-corp',
  status: 'ACTIVE',
  limitPerMinute: 60,
  limitPerHour: null,
  limitPerDay: null,
  limitPerWeek: null,
  limitPerMonth: null,
  expiresAt: null,
  revokedAt: null,
};

describe('resolveApiKeyRecordState', () => {
  it('should encode an active key without TTL', () => {
    expect(resolveApiKeyRecordState(source, NOW)).toEqual({
      value:
        '{"v":1,"id":"k1","consumer":"acme-corp","status":"active","limits":{"minute":60}}',
      expireAt: null,
    });
  });

  it('should keep an expiring key one day past its expiry, even when just expired', () => {
    const expiresAt = new Date((NOW - 60) * 1000);
    expect(
      resolveApiKeyRecordState({ ...source, expiresAt }, NOW)?.expireAt,
    ).toBe(NOW - 60 + 86_400);
  });

  it('should drop the record of a key expired for more than a day', () => {
    const expiresAt = new Date((NOW - 86_400) * 1000);
    expect(resolveApiKeyRecordState({ ...source, expiresAt }, NOW)).toBeNull();
  });

  it('should keep a revoked record one day from revokedAt, never extending it', () => {
    const revokedAt = new Date((NOW - 3600) * 1000);
    expect(
      resolveApiKeyRecordState({ ...source, status: 'REVOKED', revokedAt }, NOW)
        ?.expireAt,
    ).toBe(NOW - 3600 + 86_400);
  });

  it('should drop the record of a key revoked more than a day ago', () => {
    const revokedAt = new Date((NOW - 86_400) * 1000);
    expect(
      resolveApiKeyRecordState(
        { ...source, status: 'REVOKED', revokedAt },
        NOW,
      ),
    ).toBeNull();
  });

  it('should give a revoked key without revokedAt one day from now', () => {
    expect(
      resolveApiKeyRecordState({ ...source, status: 'REVOKED' }, NOW)?.expireAt,
    ).toBe(NOW + 86_400);
  });
});
