/**
 * Refresh idempotence (unit): inside the reuse grace period a second use of the same refresh
 * token gets the pair issued by the first rotation. The behaviour on the real database is in
 * test/db/g2-refresh-idempotent.e2e-spec.ts.
 * Also covers resetPassword hashing before it consumes the token.
 */
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
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

const jwtService = { signAsync: jest.fn(), verifyAsync: jest.fn() };
const userService = {
  getUserById: jest.fn(),
  incrementTokenVersion: jest.fn(),
  resetPassword: jest.fn(),
};
const permissionService = { getRequired: jest.fn() };

const decoded = (jti: string) => ({
  id: 'u1',
  email: 'mario@example.com',
  tokenVersion: 0,
  jti,
  fid: 'family-1',
});
const user = () =>
  Object.assign(new User(), {
    id: 'u1',
    email: 'mario@example.com',
    tokenVersion: 0,
  });
const rotatedRow = { userId: 'u1', familyId: 'family-1' };

describe('AuthService - idempotent refresh and password reset', () => {
  let service: AuthService;
  let issued: number;

  async function build(config: Record<string, unknown> = {}) {
    const values: Record<string, unknown> = {
      JWT_SECRET: 'test-jwt-secret-minimum-32-chars!!',
      REFRESH_TOKEN_SECRET: 'test-refresh-secret-min-32chars!',
      JWT_EXPIRATION: '15m',
      REFRESH_TOKEN_EXPIRATION: '7d',
      NODE_ENV: 'test',
      BCRYPT_ROUNDS: 4,
      REFRESH_REUSE_GRACE_SECONDS: 10,
      ...config,
    };
    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: JwtService, useValue: jwtService },
        { provide: ConfigService, useValue: { get: (k: string) => values[k] } },
        { provide: UserService, useValue: userService },
        { provide: PermissionService, useValue: permissionService },
        ...extraAuthProviders(),
      ],
    }).compile();
    return module.get(AuthService);
  }

  beforeEach(async () => {
    jest.restoreAllMocks();
    jest.clearAllMocks();
    resetAuthMocks();
    issued = 0;
    // Every signed token is different, so "same pair" really means "same cached result".
    jwtService.signAsync.mockImplementation(() =>
      Promise.resolve(`signed-${++issued}`),
    );
    jwtService.verifyAsync.mockResolvedValue(decoded('jti-1'));
    userService.getUserById.mockResolvedValue(user());
    mockRefreshTokenService.rotate.mockResolvedValue({
      status: 'rotated',
      token: rotatedRow,
    });
    service = await build();
  });

  describe('refreshTokens', () => {
    it('a second use of the same refresh token gets the same pair and rotates only once', async () => {
      const first = await service.refreshTokens('refresh.cookie');
      const second = await service.refreshTokens('refresh.cookie');

      expect(second).toEqual(first);
      expect(mockRefreshTokenService.rotate).toHaveBeenCalledTimes(1);
      expect(mockRefreshTokenService.create).toHaveBeenCalledTimes(1);
    });

    it('parallel requests share one rotation and all receive the same pair', async () => {
      const results = await Promise.all(
        Array.from({ length: 6 }, () =>
          service.refreshTokens('refresh.cookie'),
        ),
      );

      expect(new Set(results.map((r) => JSON.stringify(r))).size).toBe(1);
      expect(mockRefreshTokenService.rotate).toHaveBeenCalledTimes(1);
      expect(mockRefreshTokenService.create).toHaveBeenCalledTimes(1);
    });

    it('different refresh tokens are rotated independently', async () => {
      jwtService.verifyAsync
        .mockResolvedValueOnce(decoded('jti-1'))
        .mockResolvedValueOnce(decoded('jti-2'));

      const first = await service.refreshTokens('a');
      const second = await service.refreshTokens('b');

      expect(second).not.toEqual(first);
      expect(mockRefreshTokenService.rotate).toHaveBeenCalledTimes(2);
    });

    it('passes the grace period to the database, which judges the window with its own clock', async () => {
      await service.refreshTokens('refresh.cookie');

      expect(mockRefreshTokenService.rotate).toHaveBeenCalledWith('jti-1', 10);
    });

    it('a failed rotation is not cached: the next attempt is judged again', async () => {
      mockRefreshTokenService.rotate
        .mockResolvedValueOnce({ status: 'invalid' })
        .mockResolvedValueOnce({ status: 'rotated', token: rotatedRow });

      await expect(service.refreshTokens('c')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
      await expect(service.refreshTokens('c')).resolves.toBeDefined();
      expect(mockRefreshTokenService.rotate).toHaveBeenCalledTimes(2);
    });

    it('parallel requests that share a failing rotation all fail', async () => {
      mockRefreshTokenService.rotate.mockResolvedValue({ status: 'invalid' });

      const results = await Promise.allSettled([
        service.refreshTokens('c'),
        service.refreshTokens('c'),
        service.refreshTokens('c'),
      ]);

      expect(results.every((r) => r.status === 'rejected')).toBe(true);
      expect(mockRefreshTokenService.rotate).toHaveBeenCalledTimes(1);
    });

    it('stops answering from memory once the grace period is over', async () => {
      const start = Date.now();
      const clock = jest.spyOn(Date, 'now').mockReturnValue(start);
      await service.refreshTokens('refresh.cookie');

      clock.mockReturnValue(start + 10_001);
      mockRefreshTokenService.rotate.mockResolvedValue({
        status: 'reused',
        token: rotatedRow,
        withinGrace: false,
      });

      await expect(
        service.refreshTokens('refresh.cookie'),
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(mockRefreshTokenService.rotate).toHaveBeenCalledTimes(2);
      expect(mockRefreshTokenService.revokeFamily).toHaveBeenCalledWith(
        'family-1',
      );
    });

    it('with a grace of 0 nothing is cached: every second use goes to the database (and is theft)', async () => {
      service = await build({ REFRESH_REUSE_GRACE_SECONDS: 0 });
      mockRefreshTokenService.rotate
        .mockResolvedValueOnce({ status: 'rotated', token: rotatedRow })
        .mockResolvedValueOnce({
          status: 'reused',
          token: rotatedRow,
          withinGrace: false,
        });

      await service.refreshTokens('refresh.cookie');
      await expect(
        service.refreshTokens('refresh.cookie'),
      ).rejects.toBeInstanceOf(UnauthorizedException);

      expect(mockRefreshTokenService.rotate).toHaveBeenNthCalledWith(
        1,
        'jti-1',
        0,
      );
      expect(mockRefreshTokenService.revokeFamily).toHaveBeenCalledTimes(1);
      expect(userService.incrementTokenVersion).toHaveBeenCalledWith('u1');
    });
  });

  describe('reuse seen by the database', () => {
    const reused = (withinGrace: boolean) => ({
      status: 'reused',
      token: rotatedRow,
      withinGrace,
    });

    it("inside the grace period, with nothing in this instance's memory (another instance did the rotation): only rejected", async () => {
      mockRefreshTokenService.rotate.mockResolvedValue(reused(true));

      await expect(service.refreshTokens('x')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
      expect(mockRefreshTokenService.revokeFamily).not.toHaveBeenCalled();
      expect(userService.incrementTokenVersion).not.toHaveBeenCalled();
    });

    it('outside the grace period: family revoked and tokenVersion + 1', async () => {
      mockRefreshTokenService.rotate.mockResolvedValue(reused(false));

      await expect(service.refreshTokens('x')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
      expect(mockRefreshTokenService.revokeFamily).toHaveBeenCalledWith(
        'family-1',
      );
      expect(userService.incrementTokenVersion).toHaveBeenCalledWith('u1');
    });

    it('a detected replay drops the pair kept in memory for that family', async () => {
      await service.refreshTokens('latest'); // jti-1 rotated and cached
      jwtService.verifyAsync.mockResolvedValue(decoded('jti-0'));
      mockRefreshTokenService.rotate.mockResolvedValue(reused(false));
      await expect(service.refreshTokens('stolen')).rejects.toBeDefined();

      jwtService.verifyAsync.mockResolvedValue(decoded('jti-1'));
      mockRefreshTokenService.rotate.mockResolvedValue({ status: 'invalid' });

      await expect(service.refreshTokens('latest')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });
  });

  describe('a revoked session never gets its cached pair', () => {
    const cached = async () => {
      await service.refreshTokens('refresh.cookie');
      mockRefreshTokenService.rotate.mockResolvedValue({ status: 'invalid' });
    };
    const rejected = () =>
      expect(service.refreshTokens('refresh.cookie')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );

    it('after logout', async () => {
      await cached();

      await service.logout('refresh.cookie');

      await rejected();
    });

    it('after logout-all', async () => {
      await cached();

      await service.revokeSessions('u1');

      await rejected();
    });

    it('after a password reset', async () => {
      await cached();
      mockAuthTokenService.consume.mockResolvedValue('u1');

      await service.resetPassword('reset-token', 'New-Passw0rd!');

      await rejected();
    });

    it("but another user's sessions are untouched", async () => {
      await service.refreshTokens('refresh.cookie');
      mockRefreshTokenService.rotate.mockResolvedValue({ status: 'invalid' });

      await service.revokeSessions('someone-else');

      await expect(
        service.refreshTokens('refresh.cookie'),
      ).resolves.toBeDefined();
    });
  });

  describe('resetPassword', () => {
    beforeEach(() => {
      mockAuthTokenService.consume.mockResolvedValue('u1');
    });

    it('hashes the password BEFORE consuming the token', async () => {
      const hash = jest.spyOn(service, 'hashPassword');

      await service.resetPassword('reset-token', 'New-Passw0rd!');

      expect(hash).toHaveBeenCalledTimes(1);
      expect(hash.mock.invocationCallOrder[0]).toBeLessThan(
        mockAuthTokenService.consume.mock.invocationCallOrder[0],
      );
    });

    it('if hashing fails the link is not burned', async () => {
      jest
        .spyOn(service, 'hashPassword')
        .mockRejectedValue(new Error('bcrypt unavailable'));

      await expect(
        service.resetPassword('reset-token', 'New-Passw0rd!'),
      ).rejects.toThrow('bcrypt unavailable');
      expect(mockAuthTokenService.consume).not.toHaveBeenCalled();
      expect(userService.resetPassword).not.toHaveBeenCalled();
    });

    it('an invalid token costs the same hash as a valid one and changes nothing', async () => {
      mockAuthTokenService.consume.mockResolvedValue(null);
      const hash = jest.spyOn(service, 'hashPassword');

      await expect(
        service.resetPassword('bad-token', 'New-Passw0rd!'),
      ).rejects.toBeInstanceOf(BadRequestException);
      expect(hash).toHaveBeenCalledTimes(1);
      expect(userService.resetPassword).not.toHaveBeenCalled();
      expect(mockRefreshTokenService.revokeAllForUser).not.toHaveBeenCalled();
    });

    it('stores the hash it computed and revokes the sessions', async () => {
      jest.spyOn(service, 'hashPassword').mockResolvedValue('hashed-new');

      await service.resetPassword('reset-token', 'New-Passw0rd!');

      expect(userService.resetPassword).toHaveBeenCalledWith(
        'u1',
        'hashed-new',
      );
      expect(mockRefreshTokenService.revokeAllForUser).toHaveBeenCalledWith(
        'u1',
      );
      expect(mockAuthTokenService.invalidateAll).toHaveBeenCalledWith('u1');
      expect(mockLoginAttemptService.reset).toHaveBeenCalledWith(
        'mario@example.com',
      );
    });
  });
});
