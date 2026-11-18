import { Logger } from '@nestjs/common';
import { CronExpression } from '@nestjs/schedule';
import { Test } from '@nestjs/testing';
// Metadata key under which @Cron stores its options (not exported by @nestjs/schedule).
const SCHEDULE_CRON_OPTIONS = 'SCHEDULE_CRON_OPTIONS';

import { AuthCleanupService } from './auth-cleanup.service';
import { AuthTokenService } from './auth-token.service';
import { RefreshTokenService } from './refresh-token.service';
import { LoginAttemptService } from './login-attempt.service';

describe('AuthCleanupService', () => {
  const refreshTokens = { deleteExpired: jest.fn() };
  const authTokens = { deleteExpired: jest.fn() };
  const loginAttempts = { deleteStale: jest.fn() };
  let service: AuthCleanupService;

  beforeEach(async () => {
    jest.resetAllMocks();
    const module = await Test.createTestingModule({
      providers: [
        AuthCleanupService,
        { provide: RefreshTokenService, useValue: refreshTokens },
        { provide: AuthTokenService, useValue: authTokens },
        { provide: LoginAttemptService, useValue: loginAttempts },
      ],
    }).compile();
    service = module.get(AuthCleanupService);
  });

  it('run: deletes expired tokens and login counters no longer needed and returns the counts', async () => {
    refreshTokens.deleteExpired.mockResolvedValue(3);
    authTokens.deleteExpired.mockResolvedValue(2);
    loginAttempts.deleteStale.mockResolvedValue(5);
    await expect(service.run()).resolves.toEqual({
      refreshTokens: 3,
      authTokens: 2,
      loginAttempts: 5,
    });
  });

  it('handleCron: a database error does not bring the process down', async () => {
    refreshTokens.deleteExpired.mockRejectedValue(new Error('db down'));
    await expect(service.handleCron()).resolves.toBeUndefined();
  });

  it('runs every hour, so the login attempt counters do not pile up for a day', () => {
    const handler = Object.getOwnPropertyDescriptor(
      AuthCleanupService.prototype,
      'handleCron',
    )?.value as object;

    const options = Reflect.getMetadata(SCHEDULE_CRON_OPTIONS, handler) as {
      cronTime: string;
    };

    expect(options.cronTime).toBe(CronExpression.EVERY_HOUR);
  });

  it('is quiet when there is nothing to remove, and logs when there is', async () => {
    const log = jest.spyOn(Logger.prototype, 'log').mockImplementation();
    const debug = jest.spyOn(Logger.prototype, 'debug').mockImplementation();
    refreshTokens.deleteExpired.mockResolvedValue(0);
    authTokens.deleteExpired.mockResolvedValue(0);
    loginAttempts.deleteStale.mockResolvedValue(0);

    await service.run();
    expect(log).not.toHaveBeenCalled();
    expect(debug).toHaveBeenCalledTimes(1);

    loginAttempts.deleteStale.mockResolvedValue(4);
    await service.run();
    expect(log).toHaveBeenCalledTimes(1);

    log.mockRestore();
    debug.mockRestore();
  });
});
