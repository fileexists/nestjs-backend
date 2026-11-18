import {
  createTrustedDeviceCookie,
  trustedDeviceCookieOptions,
  verifyTrustedDevice,
} from './trusted-device';

const SECRET = 'test-secret-with-enough-length-0123456789';

describe('trusted-device (D2: the owner is not locked out)', () => {
  it('a freshly created cookie is valid for that user and that tokenVersion', () => {
    const cookie = createTrustedDeviceCookie(SECRET, 'user-1', 3);
    expect(verifyTrustedDevice(SECRET, cookie, 'user-1', 3)).toBe(true);
  });

  it.each([
    [
      'another user',
      (c: string) => verifyTrustedDevice(SECRET, c, 'user-2', 3),
    ],
    [
      'different tokenVersion (logout-all / password reset)',
      (c: string) => verifyTrustedDevice(SECRET, c, 'user-1', 4),
    ],
    [
      'another secret',
      (c: string) =>
        verifyTrustedDevice(
          'another-secret-0123456789abcdefghij',
          c,
          'user-1',
          3,
        ),
    ],
    [
      'expired',
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
    'rejects the malformed value %j',
    (value) => {
      expect(verifyTrustedDevice(SECRET, value, 'user-1', 3)).toBe(false);
    },
  );

  it('rejects a cookie with a tampered signature or with a modified expiry/user', () => {
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

  it('the cookie is httpOnly, SameSite=Lax, limited to /api/auth and secure in production', () => {
    expect(trustedDeviceCookieOptions(false)).toMatchObject({
      httpOnly: true,
      sameSite: 'lax',
      path: '/api/auth',
      secure: false,
    });
    expect(trustedDeviceCookieOptions(true).secure).toBe(true);
  });
});
