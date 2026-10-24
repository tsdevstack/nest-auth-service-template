/**
 * Normalize Email
 *
 * Accounts are stored and looked up by the normalized address, so the same
 * mailbox typed with different letter case is one account.
 *
 * Only ASCII letters are lowercased: Unicode case folding can map a different
 * address onto an existing one (for example the Kelvin sign U+212A lowercases
 * to "k"), which would let one address reach another account.
 */

export function normalizeEmail(email: string): string {
  return email.trim().replace(/[A-Z]/g, (letter) => letter.toLowerCase());
}
