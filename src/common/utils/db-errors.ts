/** PostgreSQL code for a unique constraint violation. */
export const PG_UNIQUE_VIOLATION = '23505';

/** True if the (TypeORM/pg) error is a uniqueness violation (e.g. email already present). */
export function isUniqueViolation(error: unknown): boolean {
  const candidate = error as {
    code?: string;
    driverError?: { code?: string };
  } | null;
  return (
    candidate?.code === PG_UNIQUE_VIOLATION ||
    candidate?.driverError?.code === PG_UNIQUE_VIOLATION
  );
}
