export interface TokenPayload {
  id?: string;
  email?: string;
  tokenVersion?: number;
  iat?: number;
  exp?: number;
}

// Populated on req.user by GoogleStrategy's verify callback, before it's exchanged for a real JWT.
export interface GoogleProfilePayload {
  googleId?: string;
  email?: string;
  name?: string;
  accessToken?: string;
  refreshToken?: string;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace -- required syntax for augmenting Express's global namespace
  namespace Express {
    interface User extends TokenPayload, GoogleProfilePayload {}
  }
}
