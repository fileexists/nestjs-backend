const UNITS_MS: Record<string, number> = {
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
  w: 604_800_000,
};

/** Format accepted for the configurable durations (e.g. "15m", "7d"). */
export const DURATION_PATTERN = /^(\d+)(ms|s|m|h|d|w)$/;

/** Converts "15m" / "7d" to milliseconds. Returns 0 if the format is not valid. */
export function parseDurationMs(duration: string): number {
  const match = DURATION_PATTERN.exec(duration);
  if (!match) return 0;
  return parseInt(match[1], 10) * (UNITS_MS[match[2]] ?? 0);
}
