/**
 * The schema obtained by applying the migrations must match the one described
 * by the entities: if someone changes an entity without writing the migration (or vice versa)
 * the test flags it, instead of letting `migration:generate` find out months later.
 */
import { DataSource } from 'typeorm';
import { createDataSource, resetDatabase } from './support/database';

describe('schema (e2e, real PostgreSQL)', () => {
  let db: DataSource;

  beforeAll(async () => {
    db = await createDataSource();
    await resetDatabase(db);
  });
  afterAll(async () => {
    await db?.destroy();
  });

  it('the migrations produce the same schema as the entities (no difference)', async () => {
    const { upQueries } = await db.driver.createSchemaBuilder().log();
    expect(upQueries.map((q) => q.query)).toEqual([]);
  });

  it('deleting an assigned permission removes the links to the users, not the users', async () => {
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
