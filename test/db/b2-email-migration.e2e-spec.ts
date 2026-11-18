/**
 * B2 - The NormalizeEmails migration on "dirty" data already in the database:
 * it normalizes, handles duplicates without losing anything, creates the constraint and is reversible.
 */
import { DataSource, MigrationInterface } from 'typeorm';
import {
  assertSafeDatabaseUrl,
  e2eDatabaseUrl,
  loadMigrations,
} from './support/database';

const TARGET = 'NormalizeEmails';

function migrationsUpTo(inclusive: boolean): (new () => MigrationInterface)[] {
  const all = loadMigrations();
  const index = all.findIndex((m) => m.name.startsWith(TARGET));
  if (index < 0) throw new Error(`Migration ${TARGET} not found`);
  return all.slice(0, inclusive ? index + 1 : index);
}

function dataSource(migrations: (new () => MigrationInterface)[]): DataSource {
  return new DataSource({
    type: 'postgres',
    url: e2eDatabaseUrl(),
    entities: [],
    migrations,
  });
}

describe('B2 - NormalizeEmails migration (e2e, real PostgreSQL)', () => {
  let before: DataSource;
  let withB2: DataSource;
  const q = <T>(sql: string, params: unknown[] = []) =>
    withB2.query<T[]>(sql, params);

  const ids = {
    mixedAlone: '00000000-0000-4000-8000-000000000001',
    dupLocalOld: '00000000-0000-4000-8000-000000000002',
    dupGoogle: '00000000-0000-4000-8000-000000000003',
    spaced: '00000000-0000-4000-8000-000000000004',
    triple1: '00000000-0000-4000-8000-000000000005',
    triple2: '00000000-0000-4000-8000-000000000006',
    triple3: '00000000-0000-4000-8000-000000000007',
    clean: '00000000-0000-4000-8000-000000000008',
  };

  beforeAll(async () => {
    assertSafeDatabaseUrl(e2eDatabaseUrl());
    before = await dataSource(migrationsUpTo(false)).initialize();
    await before.query('DROP SCHEMA IF EXISTS public CASCADE');
    await before.query('CREATE SCHEMA public');
    await before.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
    await before.runMigrations();

    const insert = (
      id: string,
      email: string,
      extra: Record<string, unknown>,
      createdAt: string,
    ) =>
      before.query(
        `INSERT INTO users (id, email, password, "googleId", provider, "emailVerifiedAt", "createdAt")
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          id,
          email,
          extra.password ?? null,
          extra.googleId ?? null,
          extra.provider ?? 'local',
          extra.verified ?? null,
          createdAt,
        ],
      );

    // Single account with capitals -> only normalized
    await insert(
      ids.mixedAlone,
      'Mixed.Case@Example.com',
      { password: 'hash-mixed' },
      '2024-01-01',
    );
    // Pair: the oldest local one and the verified Google one (Google must win)
    await insert(
      ids.dupLocalOld,
      'dup@example.com',
      { password: 'hash-old-local' },
      '2024-01-01',
    );
    await insert(
      ids.dupGoogle,
      'DUP@Example.com',
      { googleId: 'g-dup', provider: 'google', verified: '2024-02-01' },
      '2024-02-01',
    );
    // Spaces at the edges
    await insert(
      ids.spaced,
      '  spaced@example.com ',
      { password: 'hash-spaced' },
      '2024-01-01',
    );
    // Triplet with no verified ones: the oldest wins
    await insert(
      ids.triple1,
      'Tri@Example.com',
      { password: 'p1' },
      '2024-01-01',
    );
    await insert(
      ids.triple2,
      'tri@example.com',
      { password: 'p2' },
      '2024-03-01',
    );
    await insert(
      ids.triple3,
      'TRI@EXAMPLE.COM',
      { password: 'p3' },
      '2024-02-01',
    );
    // Already clean
    await insert(
      ids.clean,
      'clean@example.com',
      { password: 'hash-clean' },
      '2024-01-01',
    );

    // A permission linked to a duplicate: it must not be lost.
    await before.query(
      `INSERT INTO permissions (id, name, description) VALUES ('10000000-0000-4000-8000-000000000001', 'USER', 'u')`,
    );
    await before.query(
      `INSERT INTO user_permissions (user_id, permission_id) VALUES ($1, '10000000-0000-4000-8000-000000000001')`,
      [ids.dupLocalOld],
    );

    withB2 = await dataSource(migrationsUpTo(true)).initialize();
    await withB2.runMigrations();
  });

  afterAll(async () => {
    await withB2?.destroy();
    await before?.destroy();
  });

  const row = async (id: string) =>
    (
      await q<Record<string, unknown>>(`SELECT * FROM users WHERE id = $1`, [
        id,
      ])
    )[0];

  it('loses no user', async () => {
    const [{ n }] = await q<{ n: number }>(
      'SELECT count(*)::int AS n FROM users',
    );
    expect(n).toBe(8);
  });

  it('normalizes case and spaces of the non-duplicate accounts', async () => {
    expect((await row(ids.mixedAlone)).email).toBe('mixed.case@example.com');
    expect((await row(ids.spaced)).email).toBe('spaced@example.com');
    expect((await row(ids.clean)).email).toBe('clean@example.com');
  });

  it('among duplicates the verified/Google account stays canonical, not the oldest', async () => {
    const canonical = await row(ids.dupGoogle);
    expect(canonical.email).toBe('dup@example.com');
    expect(canonical.googleId).toBe('g-dup');
    expect(canonical.emailVerifiedAt).not.toBeNull();
  });

  it('the duplicate is not deleted: email renamed, password disabled, sessions invalidated', async () => {
    const dup = await row(ids.dupLocalOld);
    expect(dup.email).toMatch(/^dup\+dup-\d+-[0-9a-f]{8}@example\.com$/);
    expect(dup.password).toBeNull();
    expect(dup.emailVerifiedAt).toBeNull();
    expect(dup.tokenVersion).toBe(1);

    // the linked permissions are still there
    const links = await q<unknown>(
      `SELECT * FROM user_permissions WHERE user_id = $1`,
      [ids.dupLocalOld],
    );
    expect(links).toHaveLength(1);
  });

  it('among duplicates with none verified the oldest stays', async () => {
    expect((await row(ids.triple1)).email).toBe('tri@example.com');
    expect((await row(ids.triple2)).email).toMatch(/^tri\+dup-/);
    expect((await row(ids.triple3)).email).toMatch(/^tri\+dup-/);
  });

  it('records every change with the original data (for manual merge)', async () => {
    const changes = await q<Record<string, unknown>>(
      `SELECT "userId", "originalEmail", "newEmail", reason, "canonicalUserId", "originalPasswordHash"
         FROM user_email_changes ORDER BY "originalEmail"`,
    );

    const forOldLocal = changes.find((c) => c.userId === ids.dupLocalOld);
    expect(forOldLocal).toMatchObject({
      originalEmail: 'dup@example.com',
      reason: 'duplicate',
      canonicalUserId: ids.dupGoogle,
      originalPasswordHash: 'hash-old-local',
    });
    expect(changes.find((c) => c.userId === ids.mixedAlone)).toMatchObject({
      originalEmail: 'Mixed.Case@Example.com',
      reason: 'normalized',
    });
    expect(changes.find((c) => c.userId === ids.clean)).toBeUndefined();
  });

  it('after the migration the database rejects case-insensitive duplicates', async () => {
    await expect(
      withB2.query(`INSERT INTO users (email) VALUES ('CLEAN@example.com')`),
    ).rejects.toMatchObject({ code: '23505' });
  });

  it('is reversible: down restores the original emails and passwords and removes the index and the log', async () => {
    await withB2.undoLastMigration();

    expect((await row(ids.mixedAlone)).email).toBe('Mixed.Case@Example.com');
    expect((await row(ids.spaced)).email).toBe('  spaced@example.com ');
    const restored = await row(ids.dupLocalOld);
    expect(restored.email).toBe('dup@example.com');
    expect(restored.password).toBe('hash-old-local');
    expect((await row(ids.dupGoogle)).email).toBe('DUP@Example.com');

    const index = await q<unknown>(
      `SELECT 1 FROM pg_indexes WHERE indexname = 'UQ_users_email_lower'`,
    );
    expect(index).toHaveLength(0);
    const table = await q<{ t: string | null }>(
      `SELECT to_regclass('public.user_email_changes') AS t`,
    );
    expect(table[0].t).toBeNull();
  });
});

describe('B2 - NormalizeEmails on a new or already clean database', () => {
  let before: DataSource;
  let withB2: DataSource | undefined;

  // Schema from scratch up to the previous migration, then (optionally) an already tidy user.
  async function prepare(seedCleanUser: boolean) {
    await withB2?.destroy();
    await before?.destroy();
    before = await dataSource(migrationsUpTo(false)).initialize();
    await before.query('DROP SCHEMA IF EXISTS public CASCADE');
    await before.query('CREATE SCHEMA public');
    await before.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
    await before.runMigrations();
    if (seedCleanUser) {
      await before.query(
        `INSERT INTO users (email, password) VALUES ('clean@example.com', 'hash')`,
      );
    }
    withB2 = await dataSource(migrationsUpTo(true)).initialize();
    await withB2.runMigrations();
  }

  const tableExists = async () =>
    (
      await withB2!.query<{ t: string | null }[]>(
        `SELECT to_regclass('public.user_email_changes') AS t`,
      )
    )[0].t !== null;

  const uniqueIndexExists = async () =>
    (
      await withB2!.query<unknown[]>(
        `SELECT 1 FROM pg_indexes WHERE indexname = 'UQ_users_email_lower'`,
      )
    ).length === 1;

  afterAll(async () => {
    await withB2?.destroy();
    await before?.destroy();
  });

  it.each([
    ['empty database', false],
    ['only emails already in order', true],
  ])(
    '%s: no archive table, uniqueness constraint present',
    async (_name, seed) => {
      await prepare(seed);

      expect(await tableExists()).toBe(false);
      expect(await uniqueIndexExists()).toBe(true);
      await withB2!.query(
        `INSERT INTO users (email) VALUES ('new@example.com')`,
      );
      await expect(
        withB2!.query(`INSERT INTO users (email) VALUES ('NEW@example.com')`),
      ).rejects.toMatchObject({ code: '23505' });
    },
  );

  it('down also works without the archive table and the migration can be run again', async () => {
    await prepare(true);

    await withB2!.undoLastMigration();
    expect(await uniqueIndexExists()).toBe(false);
    expect(await tableExists()).toBe(false);
    const [{ email }] = await withB2!.query<{ email: string }[]>(
      `SELECT email FROM users`,
    );
    expect(email).toBe('clean@example.com');

    await withB2!.runMigrations();
    expect(await uniqueIndexExists()).toBe(true);
  });
});
