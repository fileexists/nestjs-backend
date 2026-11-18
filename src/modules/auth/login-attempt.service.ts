import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash } from 'crypto';
import { Repository } from 'typeorm';
import { LoginAttempt } from '../../common/entities/login-attempt.entity';
import { normalizeEmail } from '../../common/utils/email';

/**
 * Temporary, progressive lock per ACCOUNT, on top of the per-IP limit.
 *
 * - after `maxFailed` consecutive failures the account is locked for `base` seconds; each
 *   following lock doubles, up to `max` (default 5 failures, 60 s -> 900 s);
 * - the attempt is counted BEFORE verifying the password, atomically (locked row): with
 *   parallel requests at most `maxFailed` attempts get through, not one per request;
 * - during the lock attempts are NOT evaluated or counted: they do not extend it;
 * - after a lock another `maxFailed` failures are needed for the next one (1 is not enough);
 * - the counters decay after `window` seconds without attempts; a successful login resets them;
 * - the key is the hash of the email: same behaviour for non-existent accounts.
 * The owner cannot be shut out forever: see trusted-device.ts and the password reset.
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
   * Counts a login attempt BEFORE checking the password and says whether the account is locked.
   * Everything happens with the account row locked (transaction): concurrent requests
   * queue up, so no more guesses than allowed can be made. The attempt that
   * reaches the threshold triggers the lock immediately, and a successful login clears it (reset).
   * If the account is already locked nothing is counted: attempts during the lock do not extend it.
   */
  async registerAttempt(email: string): Promise<{ locked: boolean }> {
    const identifier = LoginAttemptService.identifierFor(email);
    return this.repository.manager.transaction(async (tx) => {
      // The fake DO UPDATE locks the row (even a newly created one) until commit.
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

      // Outside the window (no attempts for too long) start again from zero.
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

  /** Successful login or password reset: start again from zero. */
  async reset(email: string): Promise<void> {
    await this.repository.delete({
      identifier: LoginAttemptService.identifierFor(email),
    });
  }

  /** Cleanup: deletes the records that are no longer locked and are outside the window. */
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
