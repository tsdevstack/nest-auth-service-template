import { API_KEY_RECORD_LIMIT_MAX } from '@tsdevstack/nest-common';

/**
 * API key management constants.
 *
 * The Redis layout, record format and TTL rules are the public contract in
 * `@tsdevstack/nest-common` (`buildApiKeyRecordKey`, `encodeApiKeyRecord`,
 * ...); the values here are this service's own choices.
 */

/** Every generated key starts with this; it tells people what the string is */
export const API_KEY_PREFIX = 'tsk_';

/** Random bytes per key (256 bits), encoded as base64url after the prefix */
export const API_KEY_RANDOM_BYTES = 32;

/** Characters of the key kept for display (`tsk_` plus 8), never enough to use it */
export const API_KEY_DISPLAY_PREFIX_LENGTH = 12;

/** Consumer names: kebab-case, starting with a letter */
export const CONSUMER_NAME_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;

/** Longest accepted consumer name */
export const CONSUMER_NAME_MAX_LENGTH = 64;

/**
 * Consumer names that would read like another kind of caller: backends see
 * `req.service === 'partner'` for key requests and `'internal'` for internal
 * calls without `X-Service-Name`.
 */
export const RESERVED_CONSUMER_NAMES: readonly string[] = [
  'internal',
  'partner',
];

/**
 * Framework service names end with this suffix (`auth-service`); consumer
 * names must not look like a service. The service list itself is not known
 * at runtime.
 */
export const SERVICE_NAME_SUFFIX = '-service';

/** Longest accepted key name (label for admins) */
export const API_KEY_NAME_MAX_LENGTH = 100;

/** Highest accepted limit per window (Postgres INTEGER, same cap as the contract) */
export const API_KEY_LIMIT_MAX = API_KEY_RECORD_LIMIT_MAX;

/**
 * Accepted expiry range (ms since epoch): from 1970 to the end of 9999.
 * Postgres and the record (epoch seconds) both hold it.
 */
export const API_KEY_EXPIRY_MIN_MS = 0;
export const API_KEY_EXPIRY_MAX_MS = Date.UTC(9999, 11, 31, 23, 59, 59, 999);

/** Expiry timestamps must carry `Z` or an explicit offset, never local time */
export const API_KEY_EXPIRY_TIMEZONE_PATTERN = /(?:Z|[+-]\d{2}:?\d{2})$/;

/** Default time both keys work after a rotation */
export const API_KEY_ROTATION_DEFAULT_GRACE_HOURS = 7 * 24;

/** Longest accepted rotation grace */
export const API_KEY_ROTATION_MAX_GRACE_HOURS = 90 * 24;

/**
 * Rebuild lock lifetime. The lock only keeps instances from rebuilding at the
 * same time; a crashed holder blocks others for at most this long.
 */
export const API_KEY_REBUILD_LOCK_TTL_MS = 5 * 60_000;

/** Keys loaded from Postgres per rebuild and usage-sync batch */
export const API_KEY_BATCH_SIZE = 500;

/**
 * Suffix of the per-counter "saved total already added" flag the rebuild
 * writes next to a week or month counter
 * (`apikey:{<h>}:seeded:week:<start>`). Private to this service; Kong never
 * reads it. It makes adding the saved totals idempotent when a rebuild is
 * interrupted and runs again.
 */
export const API_KEY_SEED_FLAG_SEGMENT = 'seeded';

/**
 * Writes a record (or deletes it) and returns the previous value and its
 * absolute expiry in ms, for an exact undo. One key only (cluster-safe).
 *
 * KEYS[1] record key; ARGV[1] new value ('' deletes); ARGV[2] expiry in epoch
 * seconds ('' for none). Returns {} or {previous, previousExpireAtMs}.
 */
export const WRITE_RECORD_SCRIPT = `
local previous = redis.call('GET', KEYS[1])
local previousAt = redis.call('PEXPIRETIME', KEYS[1])
if ARGV[1] == '' then
  redis.call('DEL', KEYS[1])
elseif ARGV[2] == '' then
  redis.call('SET', KEYS[1], ARGV[1])
else
  redis.call('SET', KEYS[1], ARGV[1], 'EXAT', ARGV[2])
end
if previous then
  return {previous, previousAt}
end
return {}
`;

/**
 * Restores the value a write replaced, but only while the key still holds
 * what that write left (a later write by someone else wins). One key only.
 *
 * KEYS[1] record key; ARGV[1] value the write left ('' if it deleted);
 * ARGV[2] previous value ('' if there was none); ARGV[3] previous absolute
 * expiry in ms ('' for none). Returns 1 when restored, 0 when left alone.
 */
export const UNDO_RECORD_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if ARGV[1] == '' then
  if current then
    return 0
  end
elseif current ~= ARGV[1] then
  return 0
end
if ARGV[2] == '' then
  redis.call('DEL', KEYS[1])
elseif ARGV[3] == '' then
  redis.call('SET', KEYS[1], ARGV[2])
else
  redis.call('SET', KEYS[1], ARGV[2], 'PXAT', ARGV[3])
end
return 1
`;

/**
 * Rebuild step for one key: writes the record only if none exists, and adds
 * the saved week and month totals to the counters once (guarded by a flag
 * per counter). Every name shares the key's hash tag (cluster-safe).
 *
 * KEYS: record, week counter, week flag, month counter, month flag.
 * ARGV: record value, record expiry ('' none), week total, week counter
 * expiry, month total, month counter expiry (epoch seconds).
 * Returns {recordWritten (0|1), countersSeeded (0..2)}.
 */
export const REBUILD_KEY_SCRIPT = `
local written = 0
local ok
if ARGV[2] == '' then
  ok = redis.call('SET', KEYS[1], ARGV[1], 'NX')
else
  ok = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EXAT', ARGV[2])
end
if ok then
  written = 1
end
local function seed(counter, flag, total, expireAt)
  if tonumber(total) > 0 and redis.call('SET', flag, '1', 'NX', 'EXAT', expireAt) then
    redis.call('INCRBY', counter, total)
    if redis.call('TTL', counter) == -1 then
      redis.call('EXPIREAT', counter, expireAt)
    end
    return 1
  end
  return 0
end
local seeded = seed(KEYS[2], KEYS[3], ARGV[3], ARGV[4]) + seed(KEYS[4], KEYS[5], ARGV[5], ARGV[6])
return {written, seeded}
`;

/**
 * Repairs a record after a failed or conflicting Postgres write: sets it to
 * the state resolved from the database, but only while it still holds what
 * our write left (a newer write by someone else wins). One key only.
 *
 * KEYS[1] record key; ARGV[1] value our write left ('' if it deleted);
 * ARGV[2] value from the database ('' deletes); ARGV[3] its expiry in epoch
 * seconds ('' for none). Returns 1 when repaired, 0 when left alone.
 */
export const REPAIR_RECORD_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if ARGV[1] == '' then
  if current then
    return 0
  end
elseif current ~= ARGV[1] then
  return 0
end
if ARGV[2] == '' then
  redis.call('DEL', KEYS[1])
elseif ARGV[3] == '' then
  redis.call('SET', KEYS[1], ARGV[2])
else
  redis.call('SET', KEYS[1], ARGV[2], 'EXAT', ARGV[3])
end
return 1
`;

/** Deletes the rebuild lock only while it holds this instance's token */
export const RELEASE_LOCK_SCRIPT = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`;
