import { toApiKeyDto } from './to-api-key-dto';
import type { ApiKey } from '../../generated/prisma/client';

const now = new Date('2026-09-29T12:00:00Z');
const row: ApiKey = {
  id: 'k1',
  name: 'n',
  prefix: 'tsk_abcdefgh',
  keyHash: 'secret-hash',
  consumer: 'acme-corp',
  createdById: 'admin-1',
  limitPerMinute: 1,
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
};

describe('toApiKeyDto', () => {
  it('should drop the hash', () => {
    expect(toApiKeyDto(row, now)).not.toHaveProperty('keyHash');
  });

  it('should derive expired from expiresAt (expired from that instant on)', () => {
    expect(toApiKeyDto(row, now).expired).toBe(false);
    expect(
      toApiKeyDto({ ...row, expiresAt: new Date(now.getTime() + 1) }, now)
        .expired,
    ).toBe(false);
    expect(toApiKeyDto({ ...row, expiresAt: now }, now).expired).toBe(true);
  });
});
