import { Test } from '@nestjs/testing';
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

  it('run: elimina token scaduti e contatori di login non piu utili e ritorna i conteggi', async () => {
    refreshTokens.deleteExpired.mockResolvedValue(3);
    authTokens.deleteExpired.mockResolvedValue(2);
    loginAttempts.deleteStale.mockResolvedValue(5);
    await expect(service.run()).resolves.toEqual({
      refreshTokens: 3,
      authTokens: 2,
      loginAttempts: 5,
    });
  });

  it('handleCron: un errore del database non fa cadere il processo', async () => {
    refreshTokens.deleteExpired.mockRejectedValue(new Error('db down'));
    await expect(service.handleCron()).resolves.toBeUndefined();
  });

  it('e pianificata: ha un decoratore @Cron sul metodo handleCron', () => {
    const handler = Object.getOwnPropertyDescriptor(
      AuthCleanupService.prototype,
      'handleCron',
    )?.value as object;
    const metadata = Reflect.getMetadataKeys(handler);
    expect(metadata.length).toBeGreaterThan(0);
  });
});
