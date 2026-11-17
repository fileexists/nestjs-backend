/**
 * D6 - Costo bcrypt configurabile (BCRYPT_ROUNDS) e re-hash trasparente al login. (PostgreSQL vero)
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

describe('D6 - bcrypt (e2e, PostgreSQL vero)', () => {
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

  it('le nuove password sono hashate con BCRYPT_ROUNDS', async () => {
    await createVerifiedUser(h, 'new@example.com');
    expect(bcrypt.getRounds(await storedHash('new@example.com'))).toBe(6);
  });

  it('al login con un hash vecchio (costo inferiore) lo rigenera con il costo attuale, senza invalidare le sessioni', async () => {
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
    expect((await login(h, 'old@example.com')).status).toBe(200); // la nuova password funziona
  });

  it('un hash gia al costo attuale non viene riscritto', async () => {
    await createVerifiedUser(h, 'same@example.com');
    const before = await storedHash('same@example.com');

    await login(h, 'same@example.com');

    expect(await storedHash('same@example.com')).toBe(before);
  });

  it('un hash con costo piu alto non viene mai abbassato', async () => {
    await createVerifiedUser(h, 'strong@example.com');
    const strong = await bcrypt.hash(PASSWORD, 8);
    await h.db.query(
      `UPDATE users SET password = $1 WHERE email = 'strong@example.com'`,
      [strong],
    );

    await login(h, 'strong@example.com');

    expect(await storedHash('strong@example.com')).toBe(strong);
  });

  it('con password sbagliata non si rigenera nulla', async () => {
    await createVerifiedUser(h, 'old@example.com');
    const legacy = await bcrypt.hash(PASSWORD, 4);
    await h.db.query(
      `UPDATE users SET password = $1 WHERE email = 'old@example.com'`,
      [legacy],
    );

    await login(h, 'old@example.com', 'Wrong-Passw0rd!');

    expect(await storedHash('old@example.com')).toBe(legacy);
  });

  it('(nessun duplicato) la tabella ha ancora un solo utente', async () => {
    await createVerifiedUser(h, 'one@example.com');
    expect(
      (await sql<{ n: number }>(h, 'SELECT count(*)::int AS n FROM users'))[0]
        .n,
    ).toBe(1);
  });
});
