import { formatApiKeyUsagePeriod } from './format-api-key-usage-period';

const at = (iso: string): number => Date.parse(iso) / 1000;

describe('formatApiKeyUsagePeriod', () => {
  it('should format ISO weeks', () => {
    expect(formatApiKeyUsagePeriod('week', at('2026-09-29T19:22:44Z'))).toBe(
      '2026-W40',
    );
    expect(formatApiKeyUsagePeriod('week', at('2026-01-05T00:00:00Z'))).toBe(
      '2026-W02',
    );
  });

  it('should use the ISO week-numbering year at year boundaries', () => {
    expect(formatApiKeyUsagePeriod('week', at('2027-01-01T12:00:00Z'))).toBe(
      '2026-W53',
    );
    expect(formatApiKeyUsagePeriod('week', at('2021-01-03T23:59:59Z'))).toBe(
      '2020-W53',
    );
    expect(formatApiKeyUsagePeriod('week', at('2024-12-30T00:00:00Z'))).toBe(
      '2025-W01',
    );
  });

  it('should format months', () => {
    expect(formatApiKeyUsagePeriod('month', at('2026-09-29T19:22:44Z'))).toBe(
      '2026-09',
    );
    expect(formatApiKeyUsagePeriod('month', at('2027-01-01T00:00:00Z'))).toBe(
      '2027-01',
    );
  });
});
