/**
 * A1 - The password is chosen at email CONFIRMATION.
 *
 * Without this, whoever registers someone else's email with a password of their own (pre-hijacking)
 * would get a verified account as soon as the victim clicks the link they receive: the attacker's
 * password would stay valid. Whoever confirms (the owner of the mailbox) sets their own
 * password, which replaces the one entered at registration.
 */
import { createHarness, Harness } from './support/harness';
import { PASSWORD, http, login, register, sql, userRow } from './support/api';

const VICTIM = 'victim@example.com';
const ATTACKER_PASSWORD = 'Attacker-Passw0rd!';
const VICTIM_PASSWORD = 'Victim-Chosen-Passw0rd!';

describe('A1 - password at confirmation (e2e, real PostgreSQL)', () => {
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

  const confirm = (token: string, password?: string) =>
    http(h)
      .post('/api/auth/verify-email')
      .send(password === undefined ? { token } : { token, password });

  it("pre-hijacking: the victim confirms with their own password and the attacker's stops working", async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const token = h.mail.lastToken(VICTIM, 'verification');

    expect((await confirm(token, VICTIM_PASSWORD)).status).toBe(200);

    expect((await login(h, VICTIM, ATTACKER_PASSWORD)).status).toBe(401);
    expect((await login(h, VICTIM, VICTIM_PASSWORD)).status).toBe(200);
  });

  it('a user who registered on their own can confirm the same password again and sign in', async () => {
    await register(h, VICTIM, PASSWORD);
    const token = h.mail.lastToken(VICTIM, 'verification');

    expect((await confirm(token, PASSWORD)).status).toBe(200);
    expect((await login(h, VICTIM, PASSWORD)).status).toBe(200);
  });

  it('without a password the confirmation is rejected and the token stays valid', async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const token = h.mail.lastToken(VICTIM, 'verification');

    expect((await confirm(token)).status).toBe(400);
    expect((await userRow(h, VICTIM))?.emailVerifiedAt).toBeNull();

    expect((await confirm(token, VICTIM_PASSWORD)).status).toBe(200);
  });

  it.each([
    ['too short', 'short'],
    ['over 72 characters', 'x'.repeat(73)],
    ['over 72 bytes', '€'.repeat(25)],
  ])('password %s: 400 and the token is not consumed', async (_label, bad) => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const token = h.mail.lastToken(VICTIM, 'verification');

    expect((await confirm(token, bad)).status).toBe(400);
    expect((await confirm(token, VICTIM_PASSWORD)).status).toBe(200);
  });

  it('only a bcrypt hash of the new password ends up in the database', async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    await confirm(h.mail.lastToken(VICTIM, 'verification'), VICTIM_PASSWORD);

    const row = await userRow(h, VICTIM);
    expect(row?.password).toMatch(/^\$2[aby]\$\d{2}\$/);
    expect(row?.password).not.toContain(VICTIM_PASSWORD);
    expect(row?.emailVerifiedAt).not.toBeNull();
  });

  it('with an invalid token answers 400 just as with a password of the wrong format (no observable difference)', async () => {
    const unknown = await confirm('x'.repeat(43), VICTIM_PASSWORD);
    expect(unknown.status).toBe(400);
    expect(unknown.body).toMatchObject({
      message: 'Invalid or expired token',
    });
  });

  it('the token is single-use with the password too: two concurrent confirmations, only one succeeds and only one password wins', async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const token = h.mail.lastToken(VICTIM, 'verification');

    const results = await Promise.all([
      confirm(token, 'First-Passw0rd-one!'),
      confirm(token, 'Second-Passw0rd-two!'),
    ]);

    expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
    const winner =
      results[0].status === 200
        ? 'First-Passw0rd-one!'
        : 'Second-Passw0rd-two!';
    const loser =
      results[0].status === 200
        ? 'Second-Passw0rd-two!'
        : 'First-Passw0rd-one!';
    expect((await login(h, VICTIM, winner)).status).toBe(200);
    expect((await login(h, VICTIM, loser)).status).toBe(401);
  });

  it('a verification token never changes the password of an already verified account', async () => {
    await register(h, VICTIM, ATTACKER_PASSWORD);
    const token = h.mail.lastToken(VICTIM, 'verification');
    // The account is verified some other way (e.g. by an administrator) but the token is still in the table.
    await h.db.query(
      `UPDATE users SET "emailVerifiedAt" = now(), password = $2 WHERE email = $1`,
      [VICTIM, await bcryptHash('Already-Verified-Passw0rd!')],
    );

    expect((await confirm(token, 'Takeover-Passw0rd-1!')).status).toBe(400);

    expect((await login(h, VICTIM, 'Already-Verified-Passw0rd!')).status).toBe(
      200,
    );
    expect((await login(h, VICTIM, 'Takeover-Passw0rd-1!')).status).toBe(401);
    const [{ n }] = await sql<{ n: number }>(
      h,
      `SELECT count(*)::int AS n FROM auth_tokens WHERE type = 'email_verification' AND "usedAt" IS NULL`,
    );
    expect(n).toBe(0); // the token is consumed anyway: it does not stay around
  });
});

async function bcryptHash(password: string): Promise<string> {
  const bcrypt = await import('bcrypt');
  return bcrypt.hash(password, 4);
}
