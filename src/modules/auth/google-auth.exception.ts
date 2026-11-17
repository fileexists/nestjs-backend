import { UnauthorizedException } from '@nestjs/common';

/** Motivo (stabile, adatto a finire in un URL) per cui l'accesso con Google e' stato rifiutato. */
export type GoogleAuthErrorCode =
  | 'state_invalid'
  | 'email_missing'
  | 'email_unverified'
  | 'account_conflict'
  | 'failed';

/** 401 con un codice: il callback lo traduce nel redirect di errore verso il frontend. */
export class GoogleAuthException extends UnauthorizedException {
  constructor(
    readonly code: GoogleAuthErrorCode,
    message: string,
  ) {
    super(message);
  }
}
