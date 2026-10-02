import { BadRequestException } from '@nestjs/common';
import { parseApiKeyExpiry } from './parse-api-key-expiry';

describe('parseApiKeyExpiry', () => {
  it('should keep null and undefined as "no expiry"', () => {
    expect(parseApiKeyExpiry(null)).toBeNull();
    expect(parseApiKeyExpiry(undefined)).toBeNull();
  });

  it('should parse UTC and offset timestamps', () => {
    expect(parseApiKeyExpiry('2026-12-31T23:59:59Z')?.toISOString()).toBe(
      '2026-12-31T23:59:59.000Z',
    );
    expect(parseApiKeyExpiry('2027-01-01T01:00:00+02:00')?.toISOString()).toBe(
      '2026-12-31T23:00:00.000Z',
    );
  });

  it.each(['not-a-date', '1969-12-31T23:59:59Z', '+010000-01-01T00:00:00Z'])(
    'should reject %s with 400',
    (value) => {
      expect(() => parseApiKeyExpiry(value)).toThrow(BadRequestException);
    },
  );

  it('should accept the bounds', () => {
    expect(parseApiKeyExpiry('1970-01-01T00:00:00Z')?.getTime()).toBe(0);
    expect(parseApiKeyExpiry('9999-12-31T23:59:59.999Z')).not.toBeNull();
  });
});
