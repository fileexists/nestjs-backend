import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { AuthTokenService } from './auth-token.service';
import { LoginAttemptService } from './login-attempt.service';
import { RefreshTokenService } from './refresh-token.service';

export interface CleanupResult {
  refreshTokens: number;
  authTokens: number;
  loginAttempts: number;
}

/** Periodic cleanup of expired tokens (refresh tokens and single-use tokens). */
@Injectable()
export class AuthCleanupService {
  private readonly logger = new Logger(AuthCleanupService.name);

  constructor(
    private readonly refreshTokenService: RefreshTokenService,
    private readonly authTokenService: AuthTokenService,
    private readonly loginAttemptService: LoginAttemptService,
  ) {}

  /**
   * Every hour (not once a day): the login attempt counters are written for ANY email, existing or
   * not, so they must not pile up for a whole day. Every instance runs it; the DELETEs are
   * idempotent, so running it more than once at the same time is harmless.
   */
  @Cron(CronExpression.EVERY_HOUR)
  async handleCron(): Promise<void> {
    try {
      await this.run();
    } catch (error) {
      this.logger.error(
        `Token cleanup failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  async run(): Promise<CleanupResult> {
    const result: CleanupResult = {
      refreshTokens: await this.refreshTokenService.deleteExpired(),
      authTokens: await this.authTokenService.deleteExpired(),
      loginAttempts: await this.loginAttemptService.deleteStale(),
    };
    const message = `Cleanup: ${result.refreshTokens} refresh tokens, ${result.authTokens} one-time tokens and ${result.loginAttempts} expired login counters removed`;
    // Hourly: only say something when there was something to remove.
    if (result.refreshTokens + result.authTokens + result.loginAttempts > 0) {
      this.logger.log(message);
    } else {
      this.logger.debug(message);
    }
    return result;
  }
}
