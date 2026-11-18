/** E - password reset (unit). The behaviour on the real database is in test/db/e-password-reset.e2e-spec.ts. */
import { BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import * as bcrypt from 'bcrypt';
import { AuthTokenType } from '../../common/entities/auth-token.entity';
import { User } from '../../common/entities/user.entity';
import { PermissionService } from '../permission/permission.service';
import { UserService } from '../user/user.service';
import { AuthService } from './auth.service';
import {
  extraAuthProviders,
  mockAuthTokenService,
  mockLoginAttemptService,
  mockRefreshTokenService,
  resetAuthMocks,
} from './testing/auth-mocks';

const userService = { getUserById: jest.fn(), resetPassword: jest.fn() };

describe('AuthService.resetPassword (E)', () => {
  let service: AuthService;
  const user = Object.assign(new User(), {
    id: 'u1',
    email: 'mario@example.com',
  });

  beforeEach(async () => {
    jest.resetAllMocks();
    resetAuthMocks();
    const config: Record<string, unknown> = {
      JWT_SECRET: 'test-jwt-secret-minimum-32-chars!!',
      REFRESH_TOKEN_SECRET: 'test-refresh-secret-min-32chars!',
      BCRYPT_ROUNDS: 4,
    };
    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: JwtService, useValue: {} },
        { provide: ConfigService, useValue: { get: (k: string) => config[k] } },
        { provide: UserService, useValue: userService },
        { provide: PermissionService, useValue: {} },
        ...extraAuthProviders(),
      ],
    }).compile();
    service = module.get(AuthService);
  });

  it('consumes the PASSWORD_RESET token and sets the new hashed password', async () => {
    mockAuthTokenService.consume.mockResolvedValue('u1');
    userService.getUserById.mockResolvedValue(user);

    await service.resetPassword('raw-token', 'Brand-New-Passw0rd!');

    expect(mockAuthTokenService.consume).toHaveBeenCalledWith(
      'raw-token',
      AuthTokenType.PASSWORD_RESET,
    );
    const [id, hash] = userService.resetPassword.mock.calls[0] as [
      string,
      string,
    ];
    expect(id).toBe('u1');
    expect(hash).not.toContain('Brand-New');
    expect(await bcrypt.compare('Brand-New-Passw0rd!', hash)).toBe(true);
    expect(bcrypt.getRounds(hash)).toBe(4);
  });

  it('invalidates everything: refresh tokens, pending tokens and the failed-attempt lock', async () => {
    mockAuthTokenService.consume.mockResolvedValue('u1');
    userService.getUserById.mockResolvedValue(user);

    await service.resetPassword('raw-token', 'Brand-New-Passw0rd!');

    expect(mockRefreshTokenService.revokeAllForUser).toHaveBeenCalledWith('u1');
    expect(mockAuthTokenService.invalidateAll).toHaveBeenCalledWith('u1');
    expect(mockLoginAttemptService.reset).toHaveBeenCalledWith(
      'mario@example.com',
    );
  });

  it('invalid, expired or already used token: 400 and no change', async () => {
    mockAuthTokenService.consume.mockResolvedValue(null);

    await expect(
      service.resetPassword('bad', 'Brand-New-Passw0rd!'),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(userService.resetPassword).not.toHaveBeenCalled();
    expect(mockRefreshTokenService.revokeAllForUser).not.toHaveBeenCalled();
    expect(mockLoginAttemptService.reset).not.toHaveBeenCalled();
  });

  it('user deleted in the meantime: 400 with the same message', async () => {
    mockAuthTokenService.consume.mockResolvedValue('u1');
    userService.getUserById.mockResolvedValue(null);

    await expect(
      service.resetPassword('t', 'Brand-New-Passw0rd!'),
    ).rejects.toThrow('Invalid or expired token');
    expect(userService.resetPassword).not.toHaveBeenCalled();
  });
});
