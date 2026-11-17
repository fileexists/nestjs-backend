const UNITS_MS: Record<string, number> = {
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
  w: 604_800_000,
};

/** Formato accettato per le durate configurabili (es. "15m", "7d"). */
export const DURATION_PATTERN = /^(\d+)(ms|s|m|h|d|w)$/;

/** Converte "15m" / "7d" in millisecondi. Ritorna 0 se il formato non e' valido. */
export function parseDurationMs(duration: string): number {
  const match = DURATION_PATTERN.exec(duration);
  if (!match) return 0;
  return parseInt(match[1], 10) * (UNITS_MS[match[2]] ?? 0);
}
