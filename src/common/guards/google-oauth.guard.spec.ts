import { ExecutionContext } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { GoogleAuthException } from '../../modules/auth/google-auth.exception';
import {
  createOAuthState,
  OAUTH_STATE_COOKIE,
} from '../../modules/auth/oauth-state';
import { GoogleCallbackGuard, GoogleOAuthGuard } from './google-oauth.guard';

const SECRET = 'test-secret-with-enough-length-0123456789';
const config = {
  getOrThrow: () => SECRET,
  get: (key: string) => (key === 'NODE_ENV' ? 'test' : undefined),
} as unknown as ConfigService;

const passportParent = () =>
  Object.getPrototypeOf(GoogleCallbackGuard.prototype) as {
    canActivate: () => Promise<boolean>;
  };

function contextWith(request: Record<string, unknown>) {
  const response = { cookie: jest.fn(), clearCookie: jest.fn() };
  const context = {
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => response,
    }),
    getHandler: jest.fn(),
    getClass: jest.fn(),
  } as unknown as ExecutionContext;
  return { context, response };
}

describe('GoogleCallbackGuard (B3)', () => {
  const guard = new GoogleCallbackGuard(config);
  // La parte Passport (classe padre, memoizzata e condivisa dai due guard) e' sostituita:
  // qui si testa solo la verifica dello state.
  let passport: jest.SpyInstance;
  beforeAll(() => {
    passport = jest
      .spyOn(passportParent(), 'canActivate')
      .mockResolvedValue(true);
  });
  beforeEach(() => passport.mockClear());
  afterAll(() => passport.mockRestore());

  it('con state e cookie coerenti prosegue verso Passport e ricorda l indice di redirect', async () => {
    const { state, cookie } = createOAuthState(SECRET, 1);
    const request: Record<string, unknown> = {
      cookies: { [OAUTH_STATE_COOKIE]: cookie },
      query: { state },
    };
    const { context, response } = contextWith(request);

    await expect(guard.canActivate(context)).resolves.toBe(true);

    expect(passport).toHaveBeenCalledTimes(1);
    expect(request.oauthRedirectIndex).toBe(1);
    expect(response.clearCookie).toHaveBeenCalledWith(
      OAUTH_STATE_COOKIE,
      expect.objectContaining({ path: '/api/auth/google' }),
    );
  });

  it.each([
    ['senza cookie', { cookies: {}, query: { state: 'x'.repeat(43) } }],
    ['senza cookie jar', { query: { state: 'x'.repeat(43) } }],
    ['senza state', { cookies: { [OAUTH_STATE_COOKIE]: 'a.0.b' }, query: {} }],
    [
      'con cookie forgiato',
      {
        cookies: {
          [OAUTH_STATE_COOKIE]: `${'n'.repeat(43)}.0.${'s'.repeat(43)}`,
        },
        query: { state: 'n'.repeat(43) },
      },
    ],
  ])(
    '%s: 401 state_invalid, Passport NON viene chiamato e il cookie viene comunque cancellato',
    async (_label, request) => {
      const { context, response } = contextWith(request);

      const error = await guard.canActivate(context).catch((e: unknown) => e);

      expect(error).toBeInstanceOf(GoogleAuthException);
      expect((error as GoogleAuthException).code).toBe('state_invalid');
      expect((error as GoogleAuthException).getStatus()).toBe(401);
      expect(passport).not.toHaveBeenCalled();
      expect(response.clearCookie).toHaveBeenCalled();
    },
  );

  it('un cookie gia usato (cancellato) non vale per un secondo callback', async () => {
    const { state, cookie } = createOAuthState(SECRET);
    const first = contextWith({
      cookies: { [OAUTH_STATE_COOKIE]: cookie },
      query: { state },
    });
    await guard.canActivate(first.context);

    // il browser ha ricevuto la cancellazione: il secondo callback arriva senza cookie
    const second = contextWith({ cookies: {}, query: { state } });
    await expect(guard.canActivate(second.context)).rejects.toBeInstanceOf(
      GoogleAuthException,
    );
  });
});

describe('GoogleOAuthGuard (avvio flusso, B3/C2)', () => {
  const guard = new GoogleOAuthGuard(config);
  let passport: jest.SpyInstance;
  beforeAll(() => {
    passport = jest
      .spyOn(passportParent(), 'canActivate')
      .mockResolvedValue(true);
  });
  afterAll(() => passport.mockRestore());

  it('genera lo state, imposta il cookie firmato e lo passa a Passport', async () => {
    const request: Record<string, unknown> = {};
    const { context, response } = contextWith(request);

    await guard.canActivate(context);

    const [name, value, options] = response.cookie.mock.calls[0] as [
      string,
      string,
      Record<string, unknown>,
    ];
    expect(name).toBe(OAUTH_STATE_COOKIE);
    expect(value.startsWith(`${request.oauthState as string}.`)).toBe(true);
    expect(options).toMatchObject({
      httpOnly: true,
      sameSite: 'lax',
      path: '/api/auth/google',
    });
    expect(guard.getAuthenticateOptions(context)).toEqual({
      state: request.oauthState,
    });
  });

  it('non chiede accesso offline ne consenso forzato (i token Google non si usano)', () => {
    const { context } = contextWith({ oauthState: 's' });
    const options = guard.getAuthenticateOptions(context) as Record<
      string,
      unknown
    >;
    expect(options.accessType).toBeUndefined();
    expect(options.prompt).toBeUndefined();
  });
});
