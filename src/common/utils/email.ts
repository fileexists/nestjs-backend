/**
 * Canonical form of an email address: no spaces at the edges and lowercase.
 * Apply it everywhere a user is created or looked up by email: the database has
 * a unique index on lower(email) and would reject duplicates anyway.
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}
