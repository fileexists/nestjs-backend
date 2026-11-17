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
 * - il tentativo si conta PRIMA di verificare la password, in modo atomico (riga bloccata): con
 *   richieste parallele passano al massimo `maxFailed` tentativi, non uno per richiesta;
 * - durante il blocco i tentativi NON vengono valutati ne' contati: non lo prolungano;
 * - dopo un blocco servono altri `maxFailed` errori per il successivo (non basta 1);
 * - i contatori decadono dopo `window` secondi senza tentativi; un login riuscito li azzera;
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

  /**
   * Conta un tentativo di login PRIMA di controllare la password e dice se l'account e' bloccato.
   * Tutto avviene con la riga dell'account bloccata (transazione): richieste concorrenti si
   * mettono in fila, quindi non si possono fare piu' prove del consentito. Il tentativo che
   * raggiunge la soglia fa scattare il blocco subito, e un login riuscito lo cancella (reset).
   * Se l'account e' gia' bloccato non conta nulla: i tentativi durante il blocco non lo prolungano.
   */
  async registerAttempt(email: string): Promise<{ locked: boolean }> {
    const identifier = LoginAttemptService.identifierFor(email);
    return this.repository.manager.transaction(async (tx) => {
      // Il finto DO UPDATE serve a bloccare la riga (anche appena creata) fino al commit.
      const [row] = await tx.query<
        {
          failedCount: number;
          lockLevel: number;
          locked: boolean;
          stale: boolean;
        }[]
      >(
        `INSERT INTO "login_attempts" ("identifier") VALUES ($1)
         ON CONFLICT ("identifier") DO UPDATE SET "identifier" = EXCLUDED."identifier"
         RETURNING "failedCount", "lockLevel",
                   COALESCE("lockedUntil" > now(), false) AS "locked",
                   ("lastFailedAt" < now() - make_interval(secs => $2::double precision)) AS "stale"`,
        [identifier, this.windowSeconds],
      );
      if (row.locked) return { locked: true };

      // Fuori finestra (nessun tentativo da troppo tempo) si riparte da zero.
      const level = row.stale ? 0 : row.lockLevel;
      const count = (row.stale ? 0 : row.failedCount) + 1;

      if (count >= this.maxFailed) {
        await tx.query(
          `UPDATE "login_attempts"
              SET "lockedUntil" = now() + make_interval(secs => LEAST($2::double precision, $3::double precision * power(2, $4::int))),
                  "lockLevel" = LEAST($4::int + 1, 30),
                  "failedCount" = 0,
                  "lastFailedAt" = now()
            WHERE "identifier" = $1`,
          [identifier, this.maxLockSeconds, this.baseLockSeconds, level],
        );
      } else {
        await tx.query(
          `UPDATE "login_attempts"
              SET "failedCount" = $2, "lockLevel" = $3, "lastFailedAt" = now()
            WHERE "identifier" = $1`,
          [identifier, count, level],
        );
      }
      return { locked: false };
    });
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
