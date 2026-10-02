import { buildApiKeySeedFlagKey } from './build-api-key-seed-flag-key';

const HASH = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
const NOW = 1790709764;

describe('buildApiKeySeedFlagKey', () => {
  it('should sit next to the counter under the same hash tag', () => {
    expect(buildApiKeySeedFlagKey(HASH, 'week', NOW)).toBe(
      `apikey:{${HASH}}:seeded:week:1790553600`,
    );
    expect(buildApiKeySeedFlagKey(HASH, 'month', NOW)).toBe(
      `apikey:{${HASH}}:seeded:month:2026-09`,
    );
  });
});
