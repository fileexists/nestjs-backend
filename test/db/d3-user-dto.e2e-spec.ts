/**
 * D3 - GET /user/me restituisce solo i campi pubblici (PostgreSQL vero).
 * Prima restituiva l'entita intera, tokenVersion compreso.
 */
import { createHarness, Harness } from './support/harness';
import {
  cookieHeader,
  createVerifiedUser,
  http,
  loginSession,
} from './support/api';
import { googleLogin } from './support/google';

describe('D3 - UserResponseDto (e2e, PostgreSQL vero)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await createHarness();
  });
  afterAll(async () => {
    await h?.close();
  });
  beforeEach(async () => {
    await h.reset();
  });

  const me = async (access: string) =>
    http(h).get('/api/user/me').set('Cookie', cookieHeader({ access }));

  it('espone esattamente i campi pubblici e nessun campo interno', async () => {
    await createVerifiedUser(h, 'mario@example.com');
    const { access } = await loginSession(h, 'mario@example.com');

    const res = await me(access);

    expect(res.status).toBe(200);
    const body = res.body as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      'createdAt',
      'email',
      'emailVerified',
      'id',
      'permissions',
      'provider',
      'updatedAt',
    ]);
    expect(body.email).toBe('mario@example.com');
    expect(body.emailVerified).toBe(true);
  });

  it.each(['tokenVersion', 'password', 'googleId', 'emailVerifiedAt'])(
    'non contiene il campo interno "%s", nemmeno annidato',
    async (field) => {
      await createVerifiedUser(h, 'mario@example.com');
      const { access } = await loginSession(h, 'mario@example.com');

      const res = await me(access);

      expect(JSON.stringify(res.body)).not.toContain(`"${field}"`);
    },
  );

  it('i permessi espongono solo id, name e description (niente relazione users)', async () => {
    await createVerifiedUser(h, 'mario@example.com');
    const { access } = await loginSession(h, 'mario@example.com');

    const { permissions } = (await me(access)).body as {
      permissions: Record<string, unknown>[];
    };

    expect(permissions.length).toBeGreaterThan(0);
    for (const permission of permissions) {
      expect(Object.keys(permission).sort()).toEqual([
        'description',
        'id',
        'name',
      ]);
    }
  });

  it('un utente creato da Google non espone googleId ne emailVerifiedAt', async () => {
    const { agent } = await googleLogin(h.app, h.google, {
      sub: 'g-secret-sub-123',
      email: 'g@example.com',
      email_verified: true,
    });

    const res = await agent.get('/api/user/me');

    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).not.toContain('g-secret-sub-123');
    expect((res.body as { provider: string }).provider).toBe('google');
  });
});
