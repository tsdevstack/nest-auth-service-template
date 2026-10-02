import { buildApiKeyRecord } from './build-api-key-record';
import type { ApiKeyRecordSource } from '../api-keys.types';

const source: ApiKeyRecordSource = {
  id: 'k1',
  consumer: 'acme-corp',
  status: 'ACTIVE',
  limitPerMinute: null,
  limitPerHour: null,
  limitPerDay: null,
  limitPerWeek: null,
  limitPerMonth: null,
  expiresAt: null,
  revokedAt: null,
};

describe('buildApiKeyRecord', () => {
  it('should omit unset limits and the expiry', () => {
    expect(buildApiKeyRecord(source)).toEqual({
      v: 1,
      id: 'k1',
      consumer: 'acme-corp',
      status: 'active',
      limits: {},
    });
  });

  it('should map every limit and the expiry in epoch seconds', () => {
    expect(
      buildApiKeyRecord({
        ...source,
        limitPerMinute: 1,
        limitPerHour: 2,
        limitPerDay: 3,
        limitPerWeek: 4,
        limitPerMonth: 5,
        expiresAt: new Date('2026-12-31T23:59:59.500Z'),
      }),
    ).toEqual({
      v: 1,
      id: 'k1',
      consumer: 'acme-corp',
      status: 'active',
      limits: { minute: 1, hour: 2, day: 3, week: 4, month: 5 },
      expiresAt: 1798761599,
    });
  });

  it('should map REVOKED to revoked', () => {
    expect(buildApiKeyRecord({ ...source, status: 'REVOKED' }).status).toBe(
      'revoked',
    );
  });
});
