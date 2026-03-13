// ---------------------------------------------------------------------------
// Module-level mock for `ms`
// ---------------------------------------------------------------------------
jest.mock('ms', () => {
  const fn = (value: string): number => {
    const map: Record<string, number> = {
      '15m': 900_000,
      '7d': 604_800_000,
      '1d': 86_400_000,
      '1h': 3_600_000,
      '30m': 1_800_000,
    };
    return map[value] ?? 60_000;
  };
  fn.default = fn;
  return fn;
});

import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { AuthService } from './auth.service';
import { User } from '../../database/user.entity';
import { Permission } from '../../database/permission.entity';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildUser(overrides: Partial<User> = {}): User {
  const user = new User();
  user.id = 'uuid-1234';
  user.email = 'test@example.com';
  user.password = '$2b$10$hashedPassword';
  user.provider = 'local';
  user.permissions = [];
  user.createdAt = new Date('2024-01-01T00:00:00.000Z');
  user.updatedAt = new Date('2024-01-01T00:00:00.000Z');
  return Object.assign(user, overrides);
}

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockJwtService: jest.Mocked<JwtService> = {
  sign: jest.fn(),
  verify: jest.fn(),
  verifyAsync: jest.fn(),
  decode: jest.fn(),
} as unknown as jest.Mocked<JwtService>;

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: JwtService, useValue: mockJwtService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // hashPassword
  // -------------------------------------------------------------------------

  describe('hashPassword', () => {
    it('should return a bcrypt hash for a given plain-text password', async () => {
      const plain = 'StrongP@ssw0rd';
      const hash = await service.hashPassword(plain);

      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
      expect(hash.startsWith('$2b$')).toBe(true);
      expect(hash).not.toBe(plain);
    });

    it('should produce unique hashes for the same password (salt randomness)', async () => {
      const plain = 'samePassword';
      const hash1 = await service.hashPassword(plain);
      const hash2 = await service.hashPassword(plain);

      expect(hash1).not.toBe(hash2);
    });
  });

  // -------------------------------------------------------------------------
  // comparePasswords
  // -------------------------------------------------------------------------

  describe('comparePasswords', () => {
    it('should return true when the plain password matches the hash', async () => {
      const plain = 'CorrectPassword';
      const hash = await bcrypt.hash(plain, 10);

      const result = await service.comparePasswords(plain, hash);

      expect(result).toBe(true);
    });

    it('should return false when the plain password does not match the hash', async () => {
      const hash = await bcrypt.hash('CorrectPassword', 10);

      const result = await service.comparePasswords('WrongPassword', hash);

      expect(result).toBe(false);
    });

    it('should return false for an empty string against a real hash', async () => {
      const hash = await bcrypt.hash('SomePassword', 10);

      const result = await service.comparePasswords('', hash);

      expect(result).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // generateJwtToken
  // -------------------------------------------------------------------------

  describe('generateJwtToken', () => {
    it('should call jwtService.sign with the correct payload and options', async () => {
      const user = buildUser();
      const fakeToken = 'signed.jwt.token';
      mockJwtService.sign.mockReturnValue(fakeToken);

      const token = await service.generateJwtToken(user);

      expect(mockJwtService.sign).toHaveBeenCalledTimes(1);
      expect(mockJwtService.sign).toHaveBeenCalledWith(
        { id: user.id, email: user.email, permissions: user.permissions },
        expect.objectContaining({ secret: expect.any(String), expiresIn: expect.any(String) }),
      );
      expect(token).toBe(fakeToken);
    });

    it('should include the user permissions array in the payload', async () => {
      const permission = new Permission();
      permission.id = 'perm-1';
      permission.name = 'USER';
      permission.description = 'Standard user';
      const user = buildUser({ permissions: [permission] });
      mockJwtService.sign.mockReturnValue('token');

      await service.generateJwtToken(user);

      const callArgs = mockJwtService.sign.mock.calls[0][0] as { permissions: Permission[] };
      expect(callArgs.permissions).toEqual([permission]);
    });
  });

  // -------------------------------------------------------------------------
  // generateRefreshToken
  // -------------------------------------------------------------------------

  describe('generateRefreshToken', () => {
    it('should return a signed refresh token string', async () => {
      const user = buildUser();
      const token = await service.generateRefreshToken(user);

      expect(typeof token).toBe('string');
      expect(token.split('.').length).toBe(3);
    });

    it('should embed the user id and email inside the refresh token payload', async () => {
      const user = buildUser();
      const token = await service.generateRefreshToken(user);
      const secret = process.env.REFRESH_TOKEN_SECRET ?? 'your_refresh_token_secret';
      const decoded = jwt.verify(token, secret) as jwt.JwtPayload;

      expect(decoded.id).toBe(user.id);
      expect(decoded.email).toBe(user.email);
    });
  });

  // -------------------------------------------------------------------------
  // verifyJwtToken
  // -------------------------------------------------------------------------

  describe('verifyJwtToken', () => {
    it('should return the decoded payload when the token is valid', async () => {
      const payload = { id: 'uuid-1', email: 'a@b.com' };
      mockJwtService.verify.mockReturnValue(payload as never);

      const result = await service.verifyJwtToken('valid.token');

      expect(result).toEqual(payload);
    });

    it('should throw UnauthorizedException when jwtService.verify throws', async () => {
      mockJwtService.verify.mockImplementation(() => {
        throw new Error('jwt expired');
      });

      await expect(service.verifyJwtToken('expired.token')).rejects.toThrow(UnauthorizedException);
      await expect(service.verifyJwtToken('expired.token')).rejects.toThrow('Invalid or expired token');
    });

    it('should throw UnauthorizedException for a completely malformed token string', async () => {
      mockJwtService.verify.mockImplementation(() => {
        throw new Error('invalid token');
      });

      await expect(service.verifyJwtToken('not-a-jwt')).rejects.toThrow(UnauthorizedException);
    });
  });

  // -------------------------------------------------------------------------
  // refreshTokens
  // -------------------------------------------------------------------------

  describe('refreshTokens', () => {
    it('should return a new access token and refresh token when the refresh token is valid', async () => {
      const user = buildUser();
      const secret = process.env.REFRESH_TOKEN_SECRET ?? 'your_refresh_token_secret';

      const validRefreshToken = jwt.sign(
        { id: user.id, email: user.email, permissions: [] },
        secret,
        { expiresIn: '7d' },
      );

      const newAccessToken = 'new.access.token';
      mockJwtService.sign.mockReturnValue(newAccessToken);

      const result = await service.refreshTokens(validRefreshToken);

      expect(result.token).toBe(newAccessToken);
      expect(typeof result.refreshToken).toBe('string');
      expect(result.refreshToken.split('.').length).toBe(3);
    });

    it('should throw UnauthorizedException when the refresh token is expired', async () => {
      const secret = process.env.REFRESH_TOKEN_SECRET ?? 'your_refresh_token_secret';
      const expiredToken = jwt.sign({ id: 'x' }, secret, { expiresIn: -1 });

      await expect(service.refreshTokens(expiredToken)).rejects.toThrow(UnauthorizedException);
      await expect(service.refreshTokens(expiredToken)).rejects.toThrow(
        'Invalid or expired refresh token',
      );
    });

    it('should throw UnauthorizedException for a completely invalid refresh token', async () => {
      await expect(service.refreshTokens('garbage.token.value')).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  // -------------------------------------------------------------------------
  // getCookieOptions
  // -------------------------------------------------------------------------

  describe('getCookieOptions', () => {
    let originalEnv: string | undefined;

    beforeEach(() => {
      originalEnv = process.env.NODE_ENV;
    });

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
    });

    it('should return accessTokenOptions and refreshTokenOptions objects', () => {
      const { accessTokenOptions, refreshTokenOptions } = service.getCookieOptions();

      expect(accessTokenOptions).toBeDefined();
      expect(refreshTokenOptions).toBeDefined();
    });

    it('refreshTokenOptions should be httpOnly', () => {
      const { refreshTokenOptions } = service.getCookieOptions();
      expect(refreshTokenOptions.httpOnly).toBe(true);
    });

    it('accessTokenOptions should NOT be httpOnly (it must be readable by the JS client)', () => {
      const { accessTokenOptions } = service.getCookieOptions();
      expect(accessTokenOptions.httpOnly).toBeFalsy();
    });

    it('both options should have sameSite set to lax', () => {
      const { accessTokenOptions, refreshTokenOptions } = service.getCookieOptions();
      expect(accessTokenOptions.sameSite).toBe('lax');
      expect(refreshTokenOptions.sameSite).toBe('lax');
    });

    it('should set secure=false in non-production environments', () => {
      process.env.NODE_ENV = 'test';
      const { accessTokenOptions, refreshTokenOptions } = service.getCookieOptions();

      expect(accessTokenOptions.secure).toBe(false);
      expect(refreshTokenOptions.secure).toBe(false);
    });

    it('should set secure=true in production environment', () => {
      process.env.NODE_ENV = 'production';
      const { accessTokenOptions, refreshTokenOptions } = service.getCookieOptions();

      expect(accessTokenOptions.secure).toBe(true);
      expect(refreshTokenOptions.secure).toBe(true);
    });

    it('accessTokenOptions should have a positive maxAge in milliseconds', () => {
      const { accessTokenOptions } = service.getCookieOptions();
      expect(typeof accessTokenOptions.maxAge).toBe('number');
      expect(accessTokenOptions.maxAge).toBe(900_000);
    });

    it('refreshTokenOptions should have a larger maxAge than accessTokenOptions', () => {
      const { accessTokenOptions, refreshTokenOptions } = service.getCookieOptions();
      expect(refreshTokenOptions.maxAge!).toBeGreaterThan(accessTokenOptions.maxAge!);
    });

    it('both options should have path set to "/"', () => {
      const { accessTokenOptions, refreshTokenOptions } = service.getCookieOptions();
      expect(accessTokenOptions.path).toBe('/');
      expect(refreshTokenOptions.path).toBe('/');
    });
  });
});