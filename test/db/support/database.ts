import * as fs from 'fs';
import * as path from 'path';
import { DataSource, MigrationInterface } from 'typeorm';
import { ENTITIES } from '../../../src/common/entities';

const MIGRATIONS_DIR = path.join(
  __dirname,
  '..',
  '..',
  '..',
  'database',
  'migrations',
);

/**
 * Safety net: the e2e tests run DROP SCHEMA. It refuses any database that
 * is not clearly a test one, so the development database is never at risk.
 */
export function assertSafeDatabaseUrl(url: string): void {
  const parsed = new URL(url);
  const dbName = parsed.pathname.replace(/^\//, '');
  const localHosts = [
    'localhost',
    '127.0.0.1',
    '::1',
    '[::1]',
    'postgres',
    'postgres-test',
  ];
  if (!/(e2e|test)/i.test(dbName) || !localHosts.includes(parsed.hostname)) {
    throw new Error(
      `Refusing to run the e2e tests on "${parsed.hostname}/${dbName}":` +
        'a local database whose name contains "e2e" or "test" is required.',
    );
  }
}

export function e2eDatabaseUrl(): string {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL not set (see test/db/setup-env.ts)');
  assertSafeDatabaseUrl(url);
  return url;
}

/** Loads the migration classes from database/migrations/*.ts (sorted by timestamp). */
export function loadMigrations(): (new () => MigrationInterface)[] {
  return fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.ts') && !f.endsWith('.d.ts'))
    .sort()
    .flatMap((file) => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const mod = require(path.join(MIGRATIONS_DIR, file)) as Record<
        string,
        unknown
      >;
      return Object.values(mod).filter(
        (v): v is new () => MigrationInterface => typeof v === 'function',
      );
    });
}

export async function createDataSource(): Promise<DataSource> {
  const dataSource = new DataSource({
    type: 'postgres',
    url: e2eDatabaseUrl(),
    entities: ENTITIES,
    migrations: loadMigrations(),
    synchronize: false,
  });
  return dataSource.initialize();
}

/** Wipes the schema and reapplies ALL the migrations: it also tests the migrations themselves. */
export async function resetDatabase(dataSource: DataSource): Promise<void> {
  assertSafeDatabaseUrl(e2eDatabaseUrl());
  await dataSource.query('DROP SCHEMA IF EXISTS public CASCADE');
  await dataSource.query('CREATE SCHEMA public');
  // InitSchema uses uuid_generate_v4(): in production TypeORM installs the extension
  // on connection, but the DROP SCHEMA above removes it.
  await dataSource.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
  await dataSource.runMigrations();
}

/** Empties the data (except `migrations` and `permissions`, which the app seeds at startup). */
export async function truncateData(dataSource: DataSource): Promise<void> {
  const rows: { tablename: string }[] = await dataSource.query(
    `SELECT tablename FROM pg_tables
      WHERE schemaname = 'public' AND tablename NOT IN ('migrations', 'permissions')`,
  );
  if (rows.length === 0) return;
  const tables = rows.map((r) => `"${r.tablename}"`).join(', ');
  await dataSource.query(`TRUNCATE TABLE ${tables} RESTART IDENTITY CASCADE`);
}
