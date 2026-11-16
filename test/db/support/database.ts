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
 * Rete di sicurezza: gli e2e fanno DROP SCHEMA. Rifiuta qualsiasi database che
 * non sia chiaramente di test, così non si rischia mai il database di sviluppo.
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
      `Rifiuto di eseguire gli e2e su "${parsed.hostname}/${dbName}": ` +
        'serve un database locale il cui nome contiene "e2e" o "test".',
    );
  }
}

export function e2eDatabaseUrl(): string {
  const url = process.env.DATABASE_URL;
  if (!url)
    throw new Error('DATABASE_URL non impostata (vedi test/db/setup-env.ts)');
  assertSafeDatabaseUrl(url);
  return url;
}

/** Carica le classi di migrazione da database/migrations/*.ts (ordinate per timestamp). */
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

/** Azzera lo schema e riapplica TUTTE le migrazioni: testa anche le migrazioni stesse. */
export async function resetDatabase(dataSource: DataSource): Promise<void> {
  assertSafeDatabaseUrl(e2eDatabaseUrl());
  await dataSource.query('DROP SCHEMA IF EXISTS public CASCADE');
  await dataSource.query('CREATE SCHEMA public');
  // InitSchema usa uuid_generate_v4(): in esercizio l'estensione la installa TypeORM
  // alla connessione, ma il DROP SCHEMA qui sopra la elimina.
  await dataSource.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
  await dataSource.runMigrations();
}

/** Svuota i dati (tranne `migrations` e `permissions`, che l'app semina all'avvio). */
export async function truncateData(dataSource: DataSource): Promise<void> {
  const rows: { tablename: string }[] = await dataSource.query(
    `SELECT tablename FROM pg_tables
      WHERE schemaname = 'public' AND tablename NOT IN ('migrations', 'permissions')`,
  );
  if (rows.length === 0) return;
  const tables = rows.map((r) => `"${r.tablename}"`).join(', ');
  await dataSource.query(`TRUNCATE TABLE ${tables} RESTART IDENTITY CASCADE`);
}
