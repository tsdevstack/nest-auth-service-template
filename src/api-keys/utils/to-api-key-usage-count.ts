/**
 * Serializes a saved usage total (Postgres BIGINT) for JSON: a number while
 * it is exact (up to `Number.MAX_SAFE_INTEGER`), a decimal string above
 * that. JSON cannot carry a bigint, and a rounded number would be wrong.
 */
export function toApiKeyUsageCount(count: bigint): number | string {
  return count <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(count)
    : count.toString();
}
