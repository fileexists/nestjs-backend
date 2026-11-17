/**
 * Lo schema ottenuto applicando le migrazioni deve coincidere con quello descritto
 * dalle entita: se qualcuno cambia un'entita senza scrivere la migrazione (o viceversa)
 * il test lo segnala, invece di lasciare che `migration:generate` lo scopra mesi dopo.
 */
import { DataSource } from 'typeorm';
import { createDataSource, resetDatabase } from './support/database';

describe('schema (e2e, PostgreSQL vero)', () => {
  let db: DataSource;

  beforeAll(async () => {
    db = await createDataSource();
    await resetDatabase(db);
  });
  afterAll(async () => {
    await db?.destroy();
  });

  it('le migrazioni producono lo stesso schema delle entita (nessuna differenza)', async () => {
    const { upQueries } = await db.driver.createSchemaBuilder().log();
    expect(upQueries.map((q) => q.query)).toEqual([]);
  });

  it('cancellare un permesso assegnato toglie i collegamenti agli utenti, non gli utenti', async () => {
    const [user] = await db.query<{ id: string }[]>(
      `INSERT INTO users (email, provider) VALUES ('fk@example.com', 'local') RETURNING id`,
    );
    const [permission] = await db.query<{ id: string }[]>(
      `INSERT INTO permissions (name, description) VALUES ('TEMP', 'x') RETURNING id`,
    );
    await db.query(
      `INSERT INTO user_permissions (user_id, permission_id) VALUES ($1, $2)`,
      [user.id, permission.id],
    );

    await db.query(`DELETE FROM permissions WHERE id = $1`, [permission.id]);

    const links = await db.query<unknown[]>(
      `SELECT 1 FROM user_permissions WHERE user_id = $1`,
      [user.id],
    );
    const users = await db.query<unknown[]>(
      `SELECT 1 FROM users WHERE id = $1`,
      [user.id],
    );
    expect(links).toHaveLength(0);
    expect(users).toHaveLength(1);
  });
});
