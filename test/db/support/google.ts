import passport from 'passport';
import request from 'supertest';
import type { App } from 'supertest/types';
import type { INestApplication } from '@nestjs/common';

/** Claim restituiti dall'endpoint userinfo di Google (OpenID Connect). */
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
 * Sostituisce SOLO le due chiamate di rete della strategia Passport "google"
 * (scambio del code e richiesta di userinfo). La vera strategia
 * passport-google-oauth20 resta in esecuzione, compreso il parsing del profilo
 * e il nostro `validate`. Non si chiama Google.
 */
export class FakeGoogle {
  private readonly userInfoByCode = new Map<string, GoogleUserInfo>();
  private counter = 0;

  /** Installa gli stub se la strategia Passport "google" e' registrata. Ritorna false se il provider e' disattivato. */
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
    if (!strategy)
      throw new Error('Strategia Passport "google" non registrata');

    strategy._oauth2.getOAuthAccessToken = (code, _params, cb) =>
      cb(null, `access-${code}`, undefined, {});
    strategy._oauth2.get = (_url, accessToken, cb) => {
      const info = this.userInfoByCode.get(accessToken.replace(/^access-/, ''));
      if (!info)
        return cb(new Error(`code Google sconosciuto: ${accessToken}`));
      cb(null, JSON.stringify(info), {});
    };
    return this;
  }

  /** Registra il profilo che Google "restituirebbe" e ritorna il `code` da presentare al callback. */
  codeFor(info: GoogleUserInfo): string {
    const code = `fake-code-${++this.counter}`;
    this.userInfoByCode.set(code, info);
    return code;
  }
}

/**
 * Esegue il flusso completo come un browser: GET /api/auth/google (legge `state`
 * dal redirect), poi GET /api/auth/google/callback con code e state.
 * `agent` conserva i cookie come un browser (rispettando Path e SameSite).
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
