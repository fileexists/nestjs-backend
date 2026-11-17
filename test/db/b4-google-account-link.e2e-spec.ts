/**
 * B4 - Google: confronto del googleId (PostgreSQL vero).
 * Prima: un utente con un googleId diverso da quello in arrivo entrava comunque
 * (e per gli account con password il googleId veniva perfino sovrascritto).
 */
import { createHarness, Harness } from './support/harness';
import {
  cookieHeader,
  cookieNames,
  cookieValue,
  createVerifiedUser,
  http,
  sql,
  userRow,
} from './support/api';
import { googleLogin } from './support/google';

describe('B4 - googleId (e2e, PostgreSQL vero)', () => {
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

  const userCount = async () =>
    (await sql<{ n: number }>(h, 'SELECT count(*)::int AS n FROM users'))[0].n;

  it('rifiuta (401) un googleId diverso da quello gia collegato e non lo sovrascrive', async () => {
    await googleLogin(h.app, h.google, {
      sub: 'g-original',
      email: 'mario@example.com',
      email_verified: true,
    });

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'g-other',
      email: 'mario@example.com',
      email_verified: true,
    });

    expect(cookieNames(callback)).not.toContain('access_token');
    expect((await userRow(h, 'mario@example.com'))?.googleId).toBe(
      'g-original',
    );
    expect(await userCount()).toBe(1);
  });

  it('un account combined (con password) non permette di sostituire il googleId', async () => {
    await createVerifiedUser(h, 'mario@example.com');
    await googleLogin(h.app, h.google, {
      sub: 'g-original',
      email: 'mario@example.com',
      email_verified: true,
    });

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'g-attacker',
      email: 'mario@example.com',
      email_verified: true,
    });

    expect(cookieNames(callback)).not.toContain('access_token');
    const row = await userRow(h, 'mario@example.com');
    expect(row?.googleId).toBe('g-original');
    expect(row?.provider).toBe('combined');
  });

  it("con lo stesso googleId ma un'email diversa (cambiata su Google) entra nello stesso account, senza crearne un secondo ne errori 500", async () => {
    await googleLogin(h.app, h.google, {
      sub: 'g-1',
      email: 'old@example.com',
      email_verified: true,
    });

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'g-1',
      email: 'new@example.com',
      email_verified: true,
    });

    expect(callback.status).toBeLessThan(400);
    expect(await userCount()).toBe(1);
    const access = cookieValue(callback, 'access_token')!;
    const me = await http(h)
      .get('/api/user/me')
      .set('Cookie', cookieHeader({ access }));
    expect(me.status).toBe(200);
    expect((me.body as { email: string }).email).toBe('old@example.com');
  });

  it("l'identita Google (sub) prevale sull'email: sub di A con email di B entra in A, non in B", async () => {
    await googleLogin(h.app, h.google, {
      sub: 'g-a',
      email: 'a@example.com',
      email_verified: true,
    });
    await createVerifiedUser(h, 'b@example.com');

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'g-a',
      email: 'b@example.com',
      email_verified: true,
    });

    expect(callback.status).toBeLessThan(400);
    const access = cookieValue(callback, 'access_token')!;
    const me = await http(h)
      .get('/api/user/me')
      .set('Cookie', cookieHeader({ access }));
    expect((me.body as { email: string }).email).toBe('a@example.com');
    expect((await userRow(h, 'b@example.com'))?.googleId).toBeNull();
  });
});
