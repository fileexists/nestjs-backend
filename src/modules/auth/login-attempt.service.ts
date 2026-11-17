import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash } from 'crypto';
import { Repository } from 'typeorm';
import { LoginAttempt } from '../../common/entities/login-attempt.entity';
import { normalizeEmail } from '../../common/utils/email';

/**
 * Blocco temporaneo e progressivo per ACCOUNT, in aggiunta al limite per IP.
 *
 * - dopo `maxFailed` errori consecutivi l'account si blocca per `base` secondi; ogni
 *   blocco successivo raddoppia, fino a `max` (default 5 errori, 60 s -> 900 s);
 * - durante il blocco i tentativi NON vengono valutati ne' contati: non lo prolungano;
 * - dopo un blocco servono altri `maxFailed` errori per il successivo (non basta 1);
 * - i contatori decadono dopo `window` secondi senza errori; un login riuscito li azzera;
 * - la chiave e' l'hash dell'email: stesso comportamento per account inesistenti.
 * Il proprietario non puo' essere escluso all'infinito: vedi trusted-device.ts e il reset password.
 */
@Injectable()
export class LoginAttemptService {
  private readonly maxFailed: number;
  private readonly baseLockSeconds: number;
  private readonly maxLockSeconds: number;
  private readonly windowSeconds: number;

  constructor(
    @InjectRepository(LoginAttempt)
    private readonly repository: Repository<LoginAttempt>,
    configService: ConfigService,
  ) {
    this.maxFailed = Number(
      configService.get<number>('LOGIN_MAX_FAILED_ATTEMPTS') ?? 5,
    );
    this.baseLockSeconds = Number(
      configService.get<number>('LOGIN_LOCK_BASE_SECONDS') ?? 60,
    );
    this.maxLockSeconds = Number(
      configService.get<number>('LOGIN_LOCK_MAX_SECONDS') ?? 900,
    );
    this.windowSeconds = Number(
      configService.get<number>('LOGIN_ATTEMPT_WINDOW_SECONDS') ?? 1800,
    );
  }

  static identifierFor(email: string): string {
    return createHash('sha256').update(normalizeEmail(email)).digest('hex');
  }

  /** Fino a quando l'account e' bloccato, o null se non lo e' (orologio del database). */
  async getLockedUntil(email: string): Promise<Date | null> {
    const rows = await this.repository.query<{ lockedUntil: Date }[]>(
      `SELECT "lockedUntil" FROM "login_attempts"
        WHERE "identifier" = $1 AND "lockedUntil" > now()`,
      [LoginAttemptService.identifierFor(email)],
    );
    return rows[0]?.lockedUntil ?? null;
  }

  /** Registra un errore (un solo upsert atomico) e, raggiunta la soglia, applica il blocco. */
  async recordFailure(email: string): Promise<void> {
    const identifier = LoginAttemptService.identifierFor(email);
    const rows = await this.repository.query<{ failedCount: number }[]>(
      `INSERT INTO "login_attempts" ("identifier", "failedCount", "lockLevel", "lastFailedAt")
       VALUES ($1, 1, 0, now())
       ON CONFLICT ("identifier") DO UPDATE SET
         "failedCount" = CASE WHEN "login_attempts"."lastFailedAt" < now() - make_interval(secs => $2::double precision)
                              THEN 1 ELSE "login_attempts"."failedCount" + 1 END,
         "lockLevel"   = CASE WHEN "login_attempts"."lastFailedAt" < now() - make_interval(secs => $2::double precision)
                              THEN 0 ELSE "login_attempts"."lockLevel" END,
         "lastFailedAt" = now()
       RETURNING "failedCount"`,
      [identifier, this.windowSeconds],
    );
    if ((rows[0]?.failedCount ?? 0) < this.maxFailed) return;

    // Il WHERE rende l'operazione idempotente con richieste concorrenti: scatta una volta sola.
    await this.repository.query(
      `UPDATE "login_attempts"
          SET "lockedUntil" = now() + make_interval(secs =>
                LEAST($2::double precision, $3::double precision * power(2, "lockLevel"))),
              "lockLevel" = LEAST("lockLevel" + 1, 30),
              "failedCount" = 0
        WHERE "identifier" = $1 AND "failedCount" >= $4`,
      [identifier, this.maxLockSeconds, this.baseLockSeconds, this.maxFailed],
    );
  }

  /** Login riuscito o password reimpostata: si riparte da zero. */
  async reset(email: string): Promise<void> {
    await this.repository.delete({
      identifier: LoginAttemptService.identifierFor(email),
    });
  }

  /** Pulizia: elimina i record non piu' bloccati e fuori dalla finestra. */
  async deleteStale(): Promise<number> {
    const result = await this.repository
      .createQueryBuilder()
      .delete()
      .from(LoginAttempt)
      .where(
        `("lockedUntil" IS NULL OR "lockedUntil" < now())
         AND "lastFailedAt" < now() - make_interval(secs => :window::double precision)`,
        { window: this.windowSeconds },
      )
      .execute();
    return result.affected ?? 0;
  }
}
