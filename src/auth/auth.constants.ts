/**
 * How long a missing or empty `ADMIN_EMAILS` secret is remembered before the
 * secret provider is asked again. Found values are cached by `SecretsService`
 * itself; missing ones are not, so without this every login would query the
 * provider (and cloud providers log a warning per miss).
 */
export const ADMIN_EMAILS_UNSET_CACHE_MS = 60_000;

/**
 * Printable ASCII only. `ADMIN_EMAILS` promotion compares addresses only when
 * the stored email matches, because case folding of other characters can map
 * a different address onto a listed one.
 */
export const ASCII_EMAIL_PATTERN = /^[\x20-\x7E]+$/;
