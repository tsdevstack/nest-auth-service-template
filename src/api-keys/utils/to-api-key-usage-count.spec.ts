import { toApiKeyUsageCount } from './to-api-key-usage-count';

describe('toApiKeyUsageCount', () => {
  it('should return numbers while exact, including above 2^31', () => {
    expect(toApiKeyUsageCount(0n)).toBe(0);
    expect(toApiKeyUsageCount(2_147_483_648n)).toBe(2_147_483_648);
    expect(toApiKeyUsageCount(9_007_199_254_740_991n)).toBe(
      Number.MAX_SAFE_INTEGER,
    );
  });

  it('should return a decimal string above MAX_SAFE_INTEGER', () => {
    expect(toApiKeyUsageCount(9_007_199_254_740_992n)).toBe('9007199254740992');
    expect(toApiKeyUsageCount(9_223_372_036_854_775_807n)).toBe(
      '9223372036854775807',
    );
  });
});
