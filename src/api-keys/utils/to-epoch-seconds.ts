/**
 * Converts a date to integer epoch seconds, rounding down (a key with a
 * fractional expiry stops working up to one second early, never late).
 */
export function toEpochSeconds(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}
