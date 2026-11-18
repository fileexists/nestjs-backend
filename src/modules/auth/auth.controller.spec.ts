import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { AccountService } from './account.service';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

describe('AuthController - uniform background responses (E)', () => {
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

  it('forgot-password: queues the work and answers immediately with a fixed message (synchronous, waits for nothing)', () => {
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

  it('forgot-password: same body for any address', () => {
    expect(controller.forgotPassword({ email: 'a@example.com' })).toEqual(
      controller.forgotPassword({ email: 'ghost@example.com' }),
    );
  });

  it('resend-verification: queues the work and answers immediately with a fixed message', () => {
    const result = controller.resendVerification({ email: 'a@example.com' });

    expect(accountService.queueResendVerification).toHaveBeenCalledWith(
      'a@example.com',
    );
    expect(result).not.toBeInstanceOf(Promise);
    expect(controller.resendVerification({ email: 'x@example.com' })).toEqual(
      result,
    );
  });

  it('reset-password: delegates to the service with the token and the new password', async () => {
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
