import {
  createOAuthState,
  OAUTH_STATE_COOKIE_PATH,
  oauthStateCookieOptions,
  verifyOAuthState,
} from './oauth-state';

const SECRET = 'test-secret-with-enough-length-0123456789';

describe('oauth-state (B3)', () => {
  it('genera un nonce casuale e un cookie che lo contiene firmato', () => {
    const { state, cookie } = createOAuthState(SECRET);

    expect(state).toMatch(/^[\w-]{40,}$/);
    expect(cookie.startsWith(`${state}.0.`)).toBe(true);
    expect(cookie.split('.')).toHaveLength(3);
  });

  it('due state non coincidono mai', () => {
    expect(createOAuthState(SECRET).state).not.toBe(
      createOAuthState(SECRET).state,
    );
  });

  it('verifica cookie e state coerenti e restituisce l indice di redirect', () => {
    const { state, cookie } = createOAuthState(SECRET, 2);
    expect(verifyOAuthState(SECRET, cookie, state)).toEqual({
      redirectIndex: 2,
    });
  });

  it.each([
    ['state assente', (c: string) => [c, undefined]],
    ['state vuoto', (c: string) => [c, '']],
    [
      'state diverso',
      (c: string) => [c, 'another-state-value-0123456789abcdef'],
    ],
    ['state non stringa', (c: string) => [c, ['a', 'b']]],
    ['cookie assente', (_c: string, s: string) => [undefined, s]],
    ['cookie non stringa', (_c: string, s: string) => [{}, s]],
    [
      'cookie senza firma',
      (c: string, s: string) => [c.split('.').slice(0, 2).join('.'), s],
    ],
    ['cookie con troppe parti', (c: string, s: string) => [`${c}.extra`, s]],
  ])('rifiuta: %s', (_label, build) => {
    const { state, cookie } = createOAuthState(SECRET);
    const [c, s] = build(cookie, state);
    expect(verifyOAuthState(SECRET, c, s)).toBeNull();
  });

  it('rifiuta una firma alterata', () => {
    const { state, cookie } = createOAuthState(SECRET);
    const tampered = `${cookie.slice(0, -2)}${cookie.endsWith('AA') ? 'BB' : 'AA'}`;
    expect(verifyOAuthState(SECRET, tampered, state)).toBeNull();
  });

  it('rifiuta se cambia l indice di redirect (e firmato insieme al nonce)', () => {
    const { state, cookie } = createOAuthState(SECRET, 0);
    const [nonce, , signature] = cookie.split('.');
    expect(
      verifyOAuthState(SECRET, `${nonce}.1.${signature}`, state),
    ).toBeNull();
  });

  it('rifiuta un indice non numerico', () => {
    const { state, cookie } = createOAuthState(SECRET);
    const [nonce, , signature] = cookie.split('.');
    expect(
      verifyOAuthState(SECRET, `${nonce}.x.${signature}`, state),
    ).toBeNull();
  });

  it('rifiuta un cookie firmato con un altro segreto', () => {
    const { state, cookie } = createOAuthState(
      'another-secret-0123456789abcdefghij',
    );
    expect(verifyOAuthState(SECRET, cookie, state)).toBeNull();
  });

  it('il cookie e httpOnly, SameSite=Lax, limitato al percorso Google e secure solo in produzione', () => {
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
