import passport from 'passport';
import request from 'supertest';
import type { App } from 'supertest/types';
import type { INestApplication } from '@nestjs/common';

/** Claims returned by Google's userinfo endpoint (OpenID Connect). */
export interface GoogleUserInfo {
  sub: string;
  email?: string;
  email_verified?: boolean | string;
  name?: string;
}

interface Oauth2Internals {
  getOAuthAccessToken: (
    code: string,
    params: unknown,
    cb: (
      err: Error | null,
      accessToken?: string,
      refreshToken?: string,
      results?: unknown,
    ) => void,
  ) => void;
  get: (
    url: string,
    accessToken: string,
    cb: (err: Error | null, body?: string, res?: unknown) => void,
  ) => void;
}

/**
 * Replaces ONLY the two network calls of the Passport "google" strategy
 * (code exchange and userinfo request). The real passport-google-oauth20
 * strategy keeps running, including the profile parsing
 * and our `validate`. Google is never called.
 */
export class FakeGoogle {
  private readonly userInfoByCode = new Map<string, GoogleUserInfo>();
  private counter = 0;

  /** Installs the stubs if the Passport "google" strategy is registered. Returns false if the provider is disabled. */
  installIfAvailable(): boolean {
    const strategy = (
      passport as unknown as {
        _strategy(name: string): unknown;
      }
    )._strategy('google');
    if (!strategy) return false;
    this.install();
    return true;
  }

  install(): this {
    const strategy = (
      passport as unknown as {
        _strategy(name: string): { _oauth2: Oauth2Internals } | undefined;
      }
    )._strategy('google');
    if (!strategy) throw new Error('Passport "google" strategy not registered');

    strategy._oauth2.getOAuthAccessToken = (code, _params, cb) =>
      cb(null, `access-${code}`, undefined, {});
    strategy._oauth2.get = (_url, accessToken, cb) => {
      const info = this.userInfoByCode.get(accessToken.replace(/^access-/, ''));
      if (!info) return cb(new Error(`unknown Google code: ${accessToken}`));
      cb(null, JSON.stringify(info), {});
    };
    return this;
  }

  /** Records the profile that Google "would return" and returns the `code` to present to the callback. */
  codeFor(info: GoogleUserInfo): string {
    const code = `fake-code-${++this.counter}`;
    this.userInfoByCode.set(code, info);
    return code;
  }
}

/**
 * Runs the whole flow like a browser: GET /api/auth/google (reads `state`
 * from the redirect), then GET /api/auth/google/callback with code and state.
 * `agent` keeps the cookies like a browser (respecting Path and SameSite).
 */
export async function googleLogin(
  app: INestApplication,
  google: FakeGoogle,
  info: GoogleUserInfo,
  agent: ReturnType<typeof request.agent> = request.agent(
    app.getHttpServer() as App,
  ),
): Promise<{
  init: request.Response;
  callback: request.Response;
  agent: typeof agent;
}> {
  const init = await agent.get('/api/auth/google');
  const location = (init.headers.location as string | undefined) ?? '';
  const state = location ? new URL(location).searchParams.get('state') : null;
  const callback = await agent
    .get('/api/auth/google/callback')
    .query({ code: google.codeFor(info), ...(state ? { state } : {}) });
  return { init, callback, agent };
}
