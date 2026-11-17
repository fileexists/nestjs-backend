/**
 * Forma canonica di un indirizzo email: senza spazi ai bordi e in minuscolo.
 * Va applicata ovunque si crei o si cerchi un utente per email: il database ha
 * un indice univoco su lower(email) e rifiuterebbe comunque i duplicati.
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}
