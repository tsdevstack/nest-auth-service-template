import { normalizeEmail } from './normalize-email';

// Built from its code point so the test reads as what it checks
const KELVIN_SIGN = String.fromCharCode(0x212a);

describe('normalizeEmail', () => {
  describe('Standard use cases', () => {
    it('should lowercase ASCII letters', () => {
      expect(normalizeEmail('John.Doe@Example.COM')).toBe(
        'john.doe@example.com',
      );
    });

    it('should trim surrounding whitespace', () => {
      expect(normalizeEmail('  john@example.com ')).toBe('john@example.com');
    });

    it('should keep an already normalized address', () => {
      expect(normalizeEmail('john@example.com')).toBe('john@example.com');
    });
  });

  describe('Edge cases', () => {
    it('should not fold the Kelvin sign onto "k"', () => {
      expect(normalizeEmail(`${KELVIN_SIGN}ate@example.com`)).toBe(
        `${KELVIN_SIGN}ate@example.com`,
      );
    });

    it('should leave other non-ASCII letters as typed', () => {
      expect(normalizeEmail('JÖRG@Example.com')).toBe('jÖrg@example.com');
    });
  });
});
