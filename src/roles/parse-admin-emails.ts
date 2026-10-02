/**
 * Parse the `ADMIN_EMAILS` secret: a comma-separated list of email addresses.
 *
 * Entries are trimmed and lowercased; empty entries are dropped.
 *
 * @param value - Raw secret value, for example `"a@example.com, B@example.com"`
 * @returns Set of normalized email addresses
 */
export function parseAdminEmails(
  value: string | undefined | null,
): Set<string> {
  const emails = new Set<string>();

  if (!value) {
    return emails;
  }

  for (const entry of value.split(',')) {
    const email = entry.trim().toLowerCase();
    if (email !== '') {
      emails.add(email);
    }
  }

  return emails;
}
