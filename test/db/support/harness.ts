import { Test } from '@nestjs/testing';
import { NestExpressApplication } from '@nestjs/platform-express';
import { ThrottlerGuard } from '@nestjs/throttler';
import { DataSource } from 'typeorm';
import { AppModule } from '../../../src/app.module';
import { MailService } from '../../../src/modules/mail/mail.service';
import { configureApp } from '../../../src/app.setup';
import { createDataSource, resetDatabase, truncateData } from './database';
import { FakeGoogle } from './google';
import { MailOutbox } from './mail-outbox';

export interface Harness {
  app: NestExpressApplication;
  /** Connessione diretta al database di test, per preparare/ispezionare i dati. */
  db: DataSource;
  /** Email "inviate" (MailService sostituito da un outbox in memoria). */
  mail: MailOutbox;
  /** Strategia Google con la rete stubbata. */
  google: FakeGoogle;
  /** Svuota i dati tra un test e l'altro. */
  reset(): Promise<void>;
  close(): Promise<void>;
}

export interface HarnessOptions {
  /** Lascia attivo il ThrottlerGuard (default: disattivato, tutte le richieste arrivano dallo stesso IP). */
  throttle?: boolean;
  /** Usa il MailService vero (SMTP): solo per i test di integrazione con Mailpit. */
  realMail?: boolean;
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
  const mail = new MailOutbox();
  if (!options.realMail) {
    builder = builder.overrideProvider(MailService).useValue(mail);
  }
  const moduleRef = await builder.compile();

  const app = moduleRef.createNestApplication<NestExpressApplication>();
  configureApp(app);
  await app.init();
  const google = new FakeGoogle();
  google.installIfAvailable();

  return {
    app,
    db,
    mail,
    google,
    reset: async () => {
      mail.clear();
      await truncateData(db);
    },
    close: async () => {
      await app.close();
      await db.destroy();
    },
  };
}
