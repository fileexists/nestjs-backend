/**
 * D6 - Configurable bcrypt cost (BCRYPT_ROUNDS) and transparent re-hash at login. (real PostgreSQL)
 */
process.env.BCRYPT_ROUNDS = '6';

import * as bcrypt from 'bcrypt';
import { createHarness, Harness } from './support/harness';
import {
  PASSWORD,
  createVerifiedUser,
  login,
  sql,
  userRow,
} from './support/api';

describe('D6 - bcrypt (e2e, real PostgreSQL)', () => {
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

  const storedHash = async (email: string) =>
    (await userRow(h, email))!.password!;

  it('new passwords are hashed with BCRYPT_ROUNDS', async () => {
    await createVerifiedUser(h, 'new@example.com');
    expect(bcrypt.getRounds(await storedHash('new@example.com'))).toBe(6);
  });

  it('at login with an old hash (lower cost) it regenerates it with the current cost, without invalidating sessions', async () => {
    await createVerifiedUser(h, 'old@example.com');
    const legacy = await bcrypt.hash(PASSWORD, 4);
    await h.db.query(
      `UPDATE users SET password = $1 WHERE email = 'old@example.com'`,
      [legacy],
    );
    const before = await userRow(h, 'old@example.com');

    const res = await login(h, 'old@example.com');
    expect(res.status).toBe(200);

    const after = await userRow(h, 'old@example.com');
    expect(bcrypt.getRounds(after!.password!)).toBe(6);
    expect(after!.password).not.toBe(legacy);
    expect(after!.tokenVersion).toBe(before!.tokenVersion);
    expect(await bcrypt.compare(PASSWORD, after!.password!)).toBe(true);
    expect((await login(h, 'old@example.com')).status).toBe(200); // the new password works
  });

  it('a hash already at the current cost is not rewritten', async () => {
    await createVerifiedUser(h, 'same@example.com');
    const before = await storedHash('same@example.com');

    await login(h, 'same@example.com');

    expect(await storedHash('same@example.com')).toBe(before);
  });

  it('a hash with a higher cost is never lowered', async () => {
    await createVerifiedUser(h, 'strong@example.com');
    const strong = await bcrypt.hash(PASSWORD, 8);
    await h.db.query(
      `UPDATE users SET password = $1 WHERE email = 'strong@example.com'`,
      [strong],
    );

    await login(h, 'strong@example.com');

    expect(await storedHash('strong@example.com')).toBe(strong);
  });

  it('with a wrong password nothing is regenerated', async () => {
    await createVerifiedUser(h, 'old@example.com');
    const legacy = await bcrypt.hash(PASSWORD, 4);
    await h.db.query(
      `UPDATE users SET password = $1 WHERE email = 'old@example.com'`,
      [legacy],
    );

    await login(h, 'old@example.com', 'Wrong-Passw0rd!');

    expect(await storedHash('old@example.com')).toBe(legacy);
  });

  it('(no duplicate) the table still has a single user', async () => {
    await createVerifiedUser(h, 'one@example.com');
    expect(
      (await sql<{ n: number }>(h, 'SELECT count(*)::int AS n FROM users'))[0]
        .n,
    ).toBe(1);
  });
});
