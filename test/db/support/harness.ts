import { Test } from '@nestjs/testing';
import { NestExpressApplication } from '@nestjs/platform-express';
import { ThrottlerGuard } from '@nestjs/throttler';
import { DataSource } from 'typeorm';
import { AppModule } from '../../../src/app.module';
import { configureApp } from '../../../src/app.setup';
import { createDataSource, resetDatabase, truncateData } from './database';

export interface Harness {
  app: NestExpressApplication;
  /** Connessione diretta al database di test, per preparare/ispezionare i dati. */
  db: DataSource;
  /** Svuota i dati tra un test e l'altro. */
  reset(): Promise<void>;
  close(): Promise<void>;
}

export interface HarnessOptions {
  /** Lascia attivo il ThrottlerGuard (default: disattivato, tutte le richieste arrivano dallo stesso IP). */
  throttle?: boolean;
}

/**
 * Avvia l'intera applicazione NestJS contro un PostgreSQL vero:
 * schema ricreato dalle migrazioni, guard/pipe/filtri identici a produzione.
 */
export async function createHarness(
  options: HarnessOptions = {},
): Promise<Harness> {
  const db = await createDataSource();
  try {
    return await boot(db, options);
  } catch (error) {
    await db.destroy();
    throw error;
  }
}

async function boot(db: DataSource, options: HarnessOptions): Promise<Harness> {
  await resetDatabase(db);

  let builder = Test.createTestingModule({ imports: [AppModule] });
  if (!options.throttle) {
    builder = builder
      .overrideProvider(ThrottlerGuard)
      .useValue({ canActivate: () => true });
  }
  const moduleRef = await builder.compile();

  const app = moduleRef.createNestApplication<NestExpressApplication>();
  configureApp(app);
  await app.init();

  return {
    app,
    db,
    reset: () => truncateData(db),
    close: async () => {
      await app.close();
      await db.destroy();
    },
  };
}
