import {
  createOAuthState,
  OAUTH_STATE_COOKIE_PATH,
  oauthStateCookieOptions,
  verifyOAuthState,
} from './oauth-state';

const SECRET = 'test-secret-with-enough-length-0123456789';

describe('oauth-state (B3)', () => {
  it('generates a random nonce and a cookie that contains it, signed', () => {
    const { state, cookie } = createOAuthState(SECRET);

    expect(state).toMatch(/^[\w-]{40,}$/);
    expect(cookie.startsWith(`${state}.0.`)).toBe(true);
    expect(cookie.split('.')).toHaveLength(3);
  });

  it('two states never coincide', () => {
    expect(createOAuthState(SECRET).state).not.toBe(
      createOAuthState(SECRET).state,
    );
  });

  it('checks that cookie and state are consistent and returns the redirect index', () => {
    const { state, cookie } = createOAuthState(SECRET, 2);
    expect(verifyOAuthState(SECRET, cookie, state)).toEqual({
      redirectIndex: 2,
    });
  });

  it.each([
    ['missing state', (c: string) => [c, undefined]],
    ['empty state', (c: string) => [c, '']],
    [
      'different state',
      (c: string) => [c, 'another-state-value-0123456789abcdef'],
    ],
    ['non-string state', (c: string) => [c, ['a', 'b']]],
    ['missing cookie', (_c: string, s: string) => [undefined, s]],
    ['non-string cookie', (_c: string, s: string) => [{}, s]],
    [
      'cookie without a signature',
      (c: string, s: string) => [c.split('.').slice(0, 2).join('.'), s],
    ],
    ['cookie with too many parts', (c: string, s: string) => [`${c}.extra`, s]],
  ])('rejects: %s', (_label, build) => {
    const { state, cookie } = createOAuthState(SECRET);
    const [c, s] = build(cookie, state);
    expect(verifyOAuthState(SECRET, c, s)).toBeNull();
  });

  it('rejects a tampered signature', () => {
    const { state, cookie } = createOAuthState(SECRET);
    const tampered = `${cookie.slice(0, -2)}${cookie.endsWith('AA') ? 'BB' : 'AA'}`;
    expect(verifyOAuthState(SECRET, tampered, state)).toBeNull();
  });

  it('rejects it if the redirect index changes (it is signed together with the nonce)', () => {
    const { state, cookie } = createOAuthState(SECRET, 0);
    const [nonce, , signature] = cookie.split('.');
    expect(
      verifyOAuthState(SECRET, `${nonce}.1.${signature}`, state),
    ).toBeNull();
  });

  it('rejects a non-numeric index', () => {
    const { state, cookie } = createOAuthState(SECRET);
    const [nonce, , signature] = cookie.split('.');
    expect(
      verifyOAuthState(SECRET, `${nonce}.x.${signature}`, state),
    ).toBeNull();
  });

  it('rejects a cookie signed with another secret', () => {
    const { state, cookie } = createOAuthState(
      'another-secret-0123456789abcdefghij',
    );
    expect(verifyOAuthState(SECRET, cookie, state)).toBeNull();
  });

  it('the cookie is httpOnly, SameSite=Lax, limited to the Google path and secure only in production', () => {
    expect(oauthStateCookieOptions(false)).toMatchObject({
      httpOnly: true,
      sameSite: 'lax',
      path: OAUTH_STATE_COOKIE_PATH,
      secure: false,
    });
    expect(oauthStateCookieOptions(true).secure).toBe(true);
    expect(oauthStateCookieOptions(false).maxAge).toBeLessThanOrEqual(600_000);
  });
});
