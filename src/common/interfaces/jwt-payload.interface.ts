export interface TokenPayload {
  id?: string;
  email?: string;
  tokenVersion?: number;
  /** Unique ID of the refresh token (recorded in `refresh_tokens`). */
  jti?: string;
  /** Family (session): the same in the access and the refresh token of a device. */
  fid?: string;
  iat?: number;
  exp?: number;
}

// Populated on req.user by GoogleStrategy's verify callback, before it's exchanged for a real JWT.
export interface GoogleProfilePayload {
  googleId?: string;
  email?: string;
  name?: string;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- required syntax for augmenting Express's global namespace
  namespace Express {
    interface User extends TokenPayload, GoogleProfilePayload {}
  }
}
