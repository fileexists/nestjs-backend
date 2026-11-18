import { UnauthorizedException } from '@nestjs/common';

/** Reason (stable, fit to end up in a URL) why the Google login was refused. */
export type GoogleAuthErrorCode =
  | 'state_invalid'
  | 'email_missing'
  | 'email_unverified'
  | 'account_conflict'
  | 'failed';

/** 401 with a code: the callback turns it into the error redirect to the frontend. */
export class GoogleAuthException extends UnauthorizedException {
  constructor(
    readonly code: GoogleAuthErrorCode,
    message: string,
  ) {
    super(message);
  }
}
