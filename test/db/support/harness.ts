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
  /** Direct connection to the test database, to prepare/inspect the data. */
  db: DataSource;
  /** "Sent" emails (MailService replaced by an in-memory outbox). */
  mail: MailOutbox;
  /** Google strategy with the network stubbed. */
  google: FakeGoogle;
  /** Empties the data between one test and the next. */
  reset(): Promise<void>;
  close(): Promise<void>;
}

export interface HarnessOptions {
  /** Keeps the ThrottlerGuard active (default: disabled, all requests come from the same IP). */
  throttle?: boolean;
  /** Uses the real MailService (SMTP): only for the integration tests with Mailpit. */
  realMail?: boolean;
}

/**
 * Starts the whole NestJS application against a real PostgreSQL:
 * schema recreated from the migrations, guards/pipes/filters identical to production.
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
