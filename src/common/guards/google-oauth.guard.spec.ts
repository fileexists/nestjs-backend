import {
  BadRequestException,
  ExecutionContext,
  NotImplementedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { GoogleAuthException } from '../../modules/auth/google-auth.exception';
import {
  createOAuthState,
  OAUTH_STATE_COOKIE,
} from '../../modules/auth/oauth-state';
import { GoogleCallbackGuard, GoogleOAuthGuard } from './google-oauth.guard';

const SECRET = 'test-secret-with-enough-length-0123456789';
const values: Record<string, string> = {
  NODE_ENV: 'test',
  GOOGLE_CLIENT_ID: 'id',
  GOOGLE_CLIENT_SECRET: 'secret',
  GOOGLE_CALLBACK_URL: 'http://localhost:5000/api/auth/google/callback',
  FRONTEND_URL: 'https://app.example.com,https://admin.example.com',
};
const configWith = (overrides: Record<string, string> = {}) =>
  ({
    getOrThrow: () => SECRET,
    get: (key: string) => ({ ...values, ...overrides })[key],
  }) as unknown as ConfigService;
const config = configWith();

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
  // The Passport part (parent class, memoized and shared by the two guards) is replaced:
  // here only the state check is tested.
  let passport: jest.SpyInstance;
  beforeAll(() => {
    passport = jest
      .spyOn(passportParent(), 'canActivate')
      .mockResolvedValue(true);
  });
  beforeEach(() => passport.mockClear());
  afterAll(() => passport.mockRestore());

  it('with a consistent state and cookie it proceeds to Passport and remembers the redirect index', async () => {
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
    ['no cookie', { cookies: {}, query: { state: 'x'.repeat(43) } }],
    ['no cookie jar', { query: { state: 'x'.repeat(43) } }],
    ['no state', { cookies: { [OAUTH_STATE_COOKIE]: 'a.0.b' }, query: {} }],
    [
      'with a forged cookie',
      {
        cookies: {
          [OAUTH_STATE_COOKIE]: `${'n'.repeat(43)}.0.${'s'.repeat(43)}`,
        },
        query: { state: 'n'.repeat(43) },
      },
    ],
  ])(
    '%s: 401 state_invalid, Passport is NOT called and the cookie is cleared anyway',
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

  it('an already used (cleared) cookie is not valid for a second callback', async () => {
    const { state, cookie } = createOAuthState(SECRET);
    const first = contextWith({
      cookies: { [OAUTH_STATE_COOKIE]: cookie },
      query: { state },
    });
    await guard.canActivate(first.context);

    // the browser received the deletion: the second callback arrives without a cookie
    const second = contextWith({ cookies: {}, query: { state } });
    await expect(guard.canActivate(second.context)).rejects.toBeInstanceOf(
      GoogleAuthException,
    );
  });
});

describe('GoogleOAuthGuard (flow start, B3/C2)', () => {
  const guard = new GoogleOAuthGuard(config);
  let passport: jest.SpyInstance;
  beforeAll(() => {
    passport = jest
      .spyOn(passportParent(), 'canActivate')
      .mockResolvedValue(true);
  });
  afterAll(() => passport.mockRestore());

  it('generates the state, sets the signed cookie and passes it to Passport', async () => {
    const request: Record<string, unknown> = { query: {} };
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

  it('asks for neither offline access nor forced consent (Google tokens are not used)', () => {
    const { context } = contextWith({ oauthState: 's' });
    const options = guard.getAuthenticateOptions(context) as Record<
      string,
      unknown
    >;
    expect(options.accessType).toBeUndefined();
    expect(options.prompt).toBeUndefined();
  });
});

describe('Google guard with the provider not configured (C2)', () => {
  const unconfigured = configWith({ GOOGLE_CLIENT_SECRET: '' });

  it.each([
    ['flow start', () => new GoogleOAuthGuard(unconfigured)],
    ['callback', () => new GoogleCallbackGuard(unconfigured)],
  ])(
    '%s: 501 and no cookie, without calling Passport',
    async (_name, build) => {
      const guard = build();
      const { context, response } = contextWith({ cookies: {}, query: {} });

      const error = await Promise.resolve()
        .then(() => guard.canActivate(context))
        .catch((e: unknown) => e);

      expect(error).toBeInstanceOf(NotImplementedException);
      expect((error as NotImplementedException).getStatus()).toBe(501);
      expect(response.cookie).not.toHaveBeenCalled();
    },
  );
});

describe('GoogleOAuthGuard - redirect_to (C1)', () => {
  const guard = new GoogleOAuthGuard(config);

  beforeAll(() => {
    jest.spyOn(passportParent(), 'canActivate').mockResolvedValue(true);
  });
  afterAll(() => jest.restoreAllMocks());

  it('signs the index of the chosen origin into the cookie (not the URL)', async () => {
    const request = { query: { redirect_to: 'https://admin.example.com' } };
    const { context, response } = contextWith(request);

    await guard.canActivate(context);

    const [, value] = response.cookie.mock.calls[0] as [string, string];
    expect(value.split('.')[1]).toBe('1');
    expect(value).not.toContain('admin.example.com');
  });

  it.each([
    'https://evil.example.com',
    'https://app.example.com.evil.com',
    'https://app.example.com@evil.com',
    '//evil.com',
    'javascript:alert(1)',
    '',
  ])('rejects redirect_to=%j with 400 and sets no cookie', async (evil) => {
    const { context, response } = contextWith({ query: { redirect_to: evil } });

    const error = await Promise.resolve()
      .then(() => guard.canActivate(context))
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(BadRequestException);
    expect(response.cookie).not.toHaveBeenCalled();
  });

  it('rejects a non-string redirect_to (e.g. an array)', async () => {
    const { context } = contextWith({ query: { redirect_to: ['a', 'b'] } });
    await expect(
      Promise.resolve().then(() => guard.canActivate(context)),
    ).rejects.toBeInstanceOf(BadRequestException);
  });
});
