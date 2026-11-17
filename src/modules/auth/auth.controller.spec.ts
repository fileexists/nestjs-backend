import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { AccountService } from './account.service';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

describe('AuthController - risposte uniformi in background (E)', () => {
  const accountService = {
    queuePasswordReset: jest.fn(),
    queueResendVerification: jest.fn(),
  };
  const authService = { resetPassword: jest.fn() };
  let controller: AuthController;

  beforeEach(async () => {
    jest.resetAllMocks();
    const module = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: authService },
        { provide: AccountService, useValue: accountService },
        {
          provide: ConfigService,
          useValue: { get: () => 'http://localhost:3000' },
        },
      ],
    }).compile();
    controller = module.get(AuthController);
  });

  it('forgot-password: accoda il lavoro e risponde subito con un messaggio fisso (sincrono, non attende nulla)', () => {
    const result = controller.forgotPassword({ email: 'a@example.com' });

    expect(accountService.queuePasswordReset).toHaveBeenCalledWith(
      'a@example.com',
    );
    expect(result).toEqual({
      message: expect.stringContaining(
        'If the address belongs to an account',
      ) as string,
    });
    expect(result).not.toBeInstanceOf(Promise);
  });

  it('forgot-password: stesso corpo per qualsiasi indirizzo', () => {
    expect(controller.forgotPassword({ email: 'a@example.com' })).toEqual(
      controller.forgotPassword({ email: 'ghost@example.com' }),
    );
  });

  it('resend-verification: accoda il lavoro e risponde subito con un messaggio fisso', () => {
    const result = controller.resendVerification({ email: 'a@example.com' });

    expect(accountService.queueResendVerification).toHaveBeenCalledWith(
      'a@example.com',
    );
    expect(result).not.toBeInstanceOf(Promise);
    expect(controller.resendVerification({ email: 'x@example.com' })).toEqual(
      result,
    );
  });

  it('reset-password: delega al servizio con token e nuova password', async () => {
    authService.resetPassword.mockResolvedValue(undefined);

    const result = await controller.resetPassword({
      token: 't'.repeat(30),
      password: 'Brand-New-Passw0rd!',
    });

    expect(authService.resetPassword).toHaveBeenCalledWith(
      't'.repeat(30),
      'Brand-New-Passw0rd!',
    );
    expect(result.message).toMatch(/log in again/i);
  });
});
