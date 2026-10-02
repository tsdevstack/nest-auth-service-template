import { toEpochSeconds } from './to-epoch-seconds';

describe('toEpochSeconds', () => {
  it('should convert to whole seconds, rounding down', () => {
    expect(toEpochSeconds(new Date('2026-09-29T19:22:44.000Z'))).toBe(
      1790709764,
    );
    expect(toEpochSeconds(new Date('2026-09-29T19:22:44.999Z'))).toBe(
      1790709764,
    );
  });
});
