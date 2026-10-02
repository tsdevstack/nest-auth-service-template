import { parseAdminEmails } from './parse-admin-emails';

describe('parseAdminEmails', () => {
  describe('Standard use cases', () => {
    it('should parse a single email', () => {
      expect(parseAdminEmails('admin@example.com')).toEqual(
        new Set(['admin@example.com']),
      );
    });

    it('should parse a comma-separated list', () => {
      expect(parseAdminEmails('a@example.com,b@example.com')).toEqual(
        new Set(['a@example.com', 'b@example.com']),
      );
    });

    it('should trim whitespace and lowercase entries', () => {
      expect(parseAdminEmails('  A@Example.com ,  b@EXAMPLE.com  ')).toEqual(
        new Set(['a@example.com', 'b@example.com']),
      );
    });
  });

  describe('Edge cases', () => {
    it('should return an empty set for an empty string', () => {
      expect(parseAdminEmails('')).toEqual(new Set());
    });

    it('should return an empty set for undefined or null', () => {
      expect(parseAdminEmails(undefined)).toEqual(new Set());
      expect(parseAdminEmails(null)).toEqual(new Set());
    });

    it('should drop empty entries', () => {
      expect(parseAdminEmails(',a@example.com,, ,')).toEqual(
        new Set(['a@example.com']),
      );
    });

    it('should deduplicate entries that differ only in case', () => {
      expect(parseAdminEmails('a@example.com,A@EXAMPLE.COM')).toEqual(
        new Set(['a@example.com']),
      );
    });
  });
});
