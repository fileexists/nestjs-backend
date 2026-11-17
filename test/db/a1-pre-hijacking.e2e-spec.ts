/**
 * A1 - Pre-hijacking dell'account (PostgreSQL vero, strategia Google con rete stubbata).
 *
 * Scenario: l'attaccante registra con email+password l'indirizzo della vittima
 * (l'email non e' verificata); la vittima poi accede con Google. La password
 * dell'attaccante NON deve restare valida.
 */
import { createHarness, Harness } from './support/harness';
import { googleLogin } from './support/google';
import {
  PASSWORD,
  browser,
  cookieNames,
  createVerifiedUser,
  http,
  login,
  register,
  sql,
  userRow,
} from './support/api';

const VICTIM = 'victim@example.com';
const ATTACKER_PASSWORD = 'AttackerPassw0rd!';

describe('A1 - pre-hijacking (e2e, PostgreSQL vero)', () => {
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

  it("la password dell'attaccante non funziona dopo il login Google della vittima", async () => {
    const registered = await register(h, VICTIM, ATTACKER_PASSWORD);
    expect(registered.status).toBeLessThan(300);

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'google-sub-victim',
      email: VICTIM,
      email_verified: true,
    });
    expect(callback.status).toBeLessThan(400);

    const attackerLogin = await login(h, VICTIM, ATTACKER_PASSWORD);
    expect(attackerLogin.status).toBe(401);
  });

  it("rivendica l'account: password azzerata, Google collegato, email verificata, sessioni invalidate", async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const before = await userRow(h, VICTIM);
    expect(before?.emailVerifiedAt).toBeNull();

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'google-sub-victim',
      email: VICTIM,
      email_verified: true,
    });
    expect(cookieNames(callback)).toContain('access_token');

    const after = await userRow(h, VICTIM);
    expect(after).toMatchObject({
      id: before?.id,
      password: null,
      googleId: 'google-sub-victim',
      provider: 'google',
      tokenVersion: (before?.tokenVersion ?? 0) + 1,
    });
    expect(after?.emailVerifiedAt).not.toBeNull();

    // I token di verifica pendenti dell'account rivendicato non servono piu.
    const [{ pending }] = await sql<{ pending: number }>(
      h,
      'SELECT count(*)::int AS pending FROM auth_tokens WHERE "userId" = $1',
      [before?.id],
    );
    expect(pending).toBe(0);
  });

  it("anche con l'email gia verificata via link, l'attaccante non puo entrare con il token di verifica rubato dopo la rivendicazione", async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const staleToken = h.mail.lastToken(VICTIM, 'verification');

    await googleLogin(h.app, h.google, {
      sub: 'google-sub-victim',
      email: VICTIM,
      email_verified: true,
    });

    const res = await http(h)
      .post('/api/auth/verify-email')
      .send({ token: staleToken });
    expect(res.status).toBe(400);
  });

  it('collega Google a un account locale GIA verificato senza toccare la password', async () => {
    await createVerifiedUser(h, 'owner@example.com');

    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'google-sub-owner',
      email: 'owner@example.com',
      email_verified: true,
    });
    expect(cookieNames(callback)).toContain('access_token');

    const row = await userRow(h, 'owner@example.com');
    expect(row).toMatchObject({
      googleId: 'google-sub-owner',
      provider: 'combined',
      tokenVersion: 0,
    });
    expect(row?.password).not.toBeNull();
    expect((await login(h, 'owner@example.com', PASSWORD)).status).toBe(200);
  });

  it('crea un utente nuovo da Google gia verificato', async () => {
    const { callback } = await googleLogin(h.app, h.google, {
      sub: 'google-sub-new',
      email: 'new@example.com',
      email_verified: true,
    });
    expect(cookieNames(callback)).toContain('access_token');
    const row = await userRow(h, 'new@example.com');
    expect(row?.emailVerifiedAt).not.toBeNull();
    expect(row?.password).toBeNull();
  });

  describe('profili Google non accettabili', () => {
    it.each([
      [
        'email_verified=false',
        { sub: 's1', email: 'x@example.com', email_verified: false },
      ],
      ['email_verified assente', { sub: 's2', email: 'x@example.com' }],
      ['email assente', { sub: 's3', email_verified: true }],
    ])(
      '%s: nessuna sessione, nessun utente creato e nessun 500',
      async (_label, info) => {
        const { callback } = await googleLogin(h.app, h.google, info);

        expect(callback.status).toBeGreaterThanOrEqual(300);
        expect(callback.status).toBeLessThan(500);
        expect(cookieNames(callback)).not.toContain('access_token');
        const [{ count }] = await sql<{ count: number }>(
          h,
          'SELECT count(*)::int AS count FROM users',
        );
        expect(count).toBe(0);
      },
    );

    it("l'email non verificata NON viene collegata a un account esistente", async () => {
      await createVerifiedUser(h, 'owner@example.com');

      await googleLogin(h.app, h.google, {
        sub: 'evil-sub',
        email: 'owner@example.com',
        email_verified: false,
      });

      const row = await userRow(h, 'owner@example.com');
      expect(row?.googleId).toBeNull();
      expect(row?.provider).toBe('local');
    });

    it('risponde 401 con un messaggio chiaro quando la strategia rifiuta il profilo', async () => {
      const agent = browser(h);
      const init = await agent.get('/api/auth/google');
      const state = new URL(init.headers.location).searchParams.get('state');
      const res = await agent.get('/api/auth/google/callback').query({
        code: h.google.codeFor({
          sub: 's9',
          email: 'x@example.com',
          email_verified: false,
        }),
        ...(state ? { state } : {}),
      });
      // Fino alla sezione C1 il callback e' JSON: 401 con messaggio. Dopo C1 e' un redirect con l'errore.
      if (res.status === 401) {
        expect(JSON.stringify(res.body)).toMatch(/not verified/i);
      } else {
        expect(res.status).toBe(302);
        expect(res.headers.location).toMatch(/status=error/);
      }
    });
  });
});
