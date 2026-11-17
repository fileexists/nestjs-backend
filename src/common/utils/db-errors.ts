/** Codice PostgreSQL della violazione di un vincolo di unicita'. */
export const PG_UNIQUE_VIOLATION = '23505';

/** True se l'errore (di TypeORM/pg) e' una violazione di unicita' (es. email gia' presente). */
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
