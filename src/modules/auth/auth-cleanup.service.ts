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

/** Pulizia periodica dei token scaduti (refresh token e token monouso). */
@Injectable()
export class AuthCleanupService {
  private readonly logger = new Logger(AuthCleanupService.name);

  constructor(
    private readonly refreshTokenService: RefreshTokenService,
    private readonly authTokenService: AuthTokenService,
    private readonly loginAttemptService: LoginAttemptService,
  ) {}

  @Cron(CronExpression.EVERY_DAY_AT_3AM)
  async handleCron(): Promise<void> {
    try {
      await this.run();
    } catch (error) {
      this.logger.error(
        `Pulizia token fallita: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  async run(): Promise<CleanupResult> {
    const result: CleanupResult = {
      refreshTokens: await this.refreshTokenService.deleteExpired(),
      authTokens: await this.authTokenService.deleteExpired(),
      loginAttempts: await this.loginAttemptService.deleteStale(),
    };
    this.logger.log(
      `Pulizia: ${result.refreshTokens} refresh token, ${result.authTokens} token monouso e ${result.loginAttempts} contatori di login scaduti rimossi`,
    );
    return result;
  }
}
