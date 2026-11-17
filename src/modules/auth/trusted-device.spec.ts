import {
  createTrustedDeviceCookie,
  trustedDeviceCookieOptions,
  verifyTrustedDevice,
} from './trusted-device';

const SECRET = 'test-secret-with-enough-length-0123456789';

describe('trusted-device (D2: il proprietario non resta fuori)', () => {
  it("un cookie appena creato vale per quell'utente e quella tokenVersion", () => {
    const cookie = createTrustedDeviceCookie(SECRET, 'user-1', 3);
    expect(verifyTrustedDevice(SECRET, cookie, 'user-1', 3)).toBe(true);
  });

  it.each([
    [
      'altro utente',
      (c: string) => verifyTrustedDevice(SECRET, c, 'user-2', 3),
    ],
    [
      'tokenVersion diverso (logout-all / reset password)',
      (c: string) => verifyTrustedDevice(SECRET, c, 'user-1', 4),
    ],
    [
      'altro segreto',
      (c: string) =>
        verifyTrustedDevice(
          'another-secret-0123456789abcdefghij',
          c,
          'user-1',
          3,
        ),
    ],
    [
      'scaduto',
      (c: string) =>
        verifyTrustedDevice(
          SECRET,
          c,
          'user-1',
          3,
          Date.now() + 31 * 86_400_000,
        ),
    ],
  ])('non vale per: %s', (_label, check) => {
    expect(check(createTrustedDeviceCookie(SECRET, 'user-1', 3))).toBe(false);
  });

  it.each([undefined, null, 42, {}, '', 'a.b.c', 'a.b.c.d.e'])(
    'rifiuta il valore malformato %j',
    (value) => {
      expect(verifyTrustedDevice(SECRET, value, 'user-1', 3)).toBe(false);
    },
  );

  it('rifiuta un cookie con firma alterata o con scadenza/utente modificati', () => {
    const [user, version, expires, signature] = createTrustedDeviceCookie(
      SECRET,
      'user-1',
      3,
    ).split('.');
    expect(
      verifyTrustedDevice(
        SECRET,
        `${user}.${version}.${expires}.${signature}x`,
        'user-1',
        3,
      ),
    ).toBe(false);
    expect(
      verifyTrustedDevice(
        SECRET,
        `${user}.${version}.${Number(expires) + 99999999}.${signature}`,
        'user-1',
        3,
      ),
    ).toBe(false);
    expect(
      verifyTrustedDevice(
        SECRET,
        `${user}.9.${expires}.${signature}`,
        'user-1',
        9,
      ),
    ).toBe(false);
  });

  it('il cookie e httpOnly, SameSite=Lax, limitato a /api/auth e secure in produzione', () => {
    expect(trustedDeviceCookieOptions(false)).toMatchObject({
      httpOnly: true,
      sameSite: 'lax',
      path: '/api/auth',
      secure: false,
    });
    expect(trustedDeviceCookieOptions(true).secure).toBe(true);
  });
});
