import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { AuthService } from './auth.service';
import { UserService } from '../user/user.service';
import { PermissionService } from '../permission/permission.service';
import { User } from '../../common/entities/user.entity';
import { Permission } from '../../common/entities/permission.entity';

function buildUser(overrides: Partial<User> = {}): User {
  const user = new User();
  user.id = 'uuid-1234';
  user.email = 'test@example.com';
  user.password = '$2b$10$hashedPassword';
  user.provider = 'local';
  user.permissions = [];
  user.tokenVersion = 0;
  user.createdAt = new Date('2024-01-01T00:00:00.000Z');
  user.updatedAt = new Date('2024-01-01T00:00:00.000Z');
  return Object.assign(user, overrides);
}

const mockJwtService: jest.Mocked<JwtService> = {
  sign: jest.fn(),
  signAsync: jest.fn(),
  verify: jest.fn(),
  verifyAsync: jest.fn(),
  decode: jest.fn(),
} as unknown as jest.Mocked<JwtService>;

const mockConfigService = {
  get: jest.fn((key: string) => {
    const config: Record<string, string> = {
      JWT_SECRET:
        process.env.JWT_SECRET ?? 'test-jwt-secret-minimum-32-chars!!',
      REFRESH_TOKEN_SECRET:
        process.env.REFRESH_TOKEN_SECRET ?? 'test-refresh-secret-min-32chars!',
      JWT_EXPIRATION: '15m',
      REFRESH_TOKEN_EXPIRATION: '7d',
      NODE_ENV: 'test',
    };
    return config[key];
  }),
};

const mockUserService = {
  getUserByEmail: jest.fn(),
  getUserById: jest.fn(),
  createUser: jest.fn(),
  updateUser: jest.fn(),
  incrementTokenVersion: jest.fn(),
};

const mockPermissionService = {
  findPermission: jest.fn(),
};

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: UserService, useValue: mockUserService },
        { provide: PermissionService, useValue: mockPermissionService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =========================================================================
  // hashPassword / comparePasswords
  // =========================================================================

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

  // =========================================================================
  // generateJwtToken
  // =========================================================================

  describe('generateJwtToken', () => {
    it('should call jwtService.signAsync with the correct payload and options', async () => {
      const user = buildUser();
      const fakeToken = 'signed.jwt.token';
      mockJwtService.signAsync.mockResolvedValue(fakeToken);

      const token = await service.generateJwtToken(user);

      expect(mockJwtService.signAsync).toHaveBeenCalledTimes(1);
      expect(mockJwtService.signAsync).toHaveBeenCalledWith(
        { id: user.id, email: user.email },
        expect.objectContaining({
          secret: expect.any(String),
          expiresIn: expect.any(String),
        }),
      );
      expect(token).toBe(fakeToken);
    });

    it('should NOT embed the permissions array in the payload (authorization is always checked live against the DB)', async () => {
      const permission = new Permission();
      permission.id = 'perm-1';
      permission.name = 'USER';
      permission.description = 'Standard user';
      const user = buildUser({ permissions: [permission] });
      mockJwtService.signAsync.mockResolvedValue('token');

      await service.generateJwtToken(user);

      const callArgs = mockJwtService.signAsync.mock.calls[0][0] as Record<
        string,
        unknown
      >;
      expect(callArgs.permissions).toBeUndefined();
    });
  });

  // =========================================================================
  // generateRefreshToken
  // =========================================================================

  describe('generateRefreshToken', () => {
    it('should call jwtService.signAsync with the correct payload (including tokenVersion) and refresh expiration', async () => {
      const user = buildUser({ tokenVersion: 3 });
      mockJwtService.signAsync.mockResolvedValue('refresh.token.value');

      const token = await service.generateRefreshToken(user);

      expect(mockJwtService.signAsync).toHaveBeenCalledTimes(1);
      expect(mockJwtService.signAsync).toHaveBeenCalledWith(
        {
          id: user.id,
          email: user.email,
          tokenVersion: user.tokenVersion,
        },
        expect.objectContaining({ expiresIn: '7d' }),
      );
      expect(token).toBe('refresh.token.value');
    });

    it('should embed user id, email and tokenVersion in the signed payload', async () => {
      const user = buildUser({ tokenVersion: 2 });
      mockJwtService.signAsync.mockResolvedValue('refresh.token');

      await service.generateRefreshToken(user);

      const callArgs = mockJwtService.signAsync.mock.calls[0][0] as {
        id: string;
        email: string;
        tokenVersion: number;
      };
      expect(callArgs.id).toBe(user.id);
      expect(callArgs.email).toBe(user.email);
      expect(callArgs.tokenVersion).toBe(2);
    });

    it('should NOT embed tokenVersion in the access token payload', async () => {
      const user = buildUser({ tokenVersion: 5 });
      mockJwtService.signAsync.mockResolvedValue('access.token');

      await service.generateJwtToken(user);

      const callArgs = mockJwtService.signAsync.mock.calls[0][0] as Record<
        string,
        unknown
      >;
      expect(callArgs.tokenVersion).toBeUndefined();
    });
  });

  // =========================================================================
  // verifyJwtToken
  // =========================================================================

  describe('verifyJwtToken', () => {
    it('should return the decoded payload when the token is valid', async () => {
      const payload = { id: 'uuid-1', email: 'a@b.com' };
      mockJwtService.verifyAsync.mockResolvedValue(payload);

      const result = await service.verifyJwtToken('valid.token');

      expect(result).toEqual(payload);
    });

    it('should throw UnauthorizedException when jwtService.verifyAsync throws', async () => {
      mockJwtService.verifyAsync.mockRejectedValue(new Error('jwt expired'));

      await expect(service.verifyJwtToken('expired.token')).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(service.verifyJwtToken('expired.token')).rejects.toThrow(
        'Invalid or expired token',
      );
    });

    it('should throw UnauthorizedException for a completely malformed token string', async () => {
      mockJwtService.verifyAsync.mockRejectedValue(new Error('invalid token'));

      await expect(service.verifyJwtToken('not-a-jwt')).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  // =========================================================================
  // refreshTokens
  // =========================================================================

  describe('refreshTokens', () => {
    it('should reload the user from the DB and return new tokens when tokenVersion matches', async () => {
      const user = buildUser({ tokenVersion: 1 });
      const decoded = {
        id: user.id,
        email: user.email,
        permissions: [],
        tokenVersion: 1,
      };

      mockJwtService.verifyAsync.mockResolvedValueOnce(decoded);
      mockUserService.getUserById.mockResolvedValueOnce(user);
      mockJwtService.signAsync.mockResolvedValueOnce('new.access.token');
      mockJwtService.signAsync.mockResolvedValueOnce('new.refresh.token');

      const result = await service.refreshTokens('valid.refresh.token');

      expect(mockUserService.getUserById).toHaveBeenCalledWith(user.id);
      expect(result.token).toBe('new.access.token');
      expect(result.refreshToken).toBe('new.refresh.token');
    });

    it('should sign the new tokens from the freshly loaded user, not the stale decoded payload', async () => {
      const user = buildUser({
        tokenVersion: 0,
        email: 'current@example.com',
      });
      const decoded = {
        id: user.id,
        email: 'stale@example.com',
        tokenVersion: 0,
      };

      mockJwtService.verifyAsync.mockResolvedValueOnce(decoded);
      mockUserService.getUserById.mockResolvedValueOnce(user);
      mockJwtService.signAsync.mockResolvedValueOnce('new.access.token');
      mockJwtService.signAsync.mockResolvedValueOnce('new.refresh.token');

      await service.refreshTokens('valid.refresh.token');

      const accessTokenCallArgs = mockJwtService.signAsync.mock.calls[0][0] as {
        email: string;
      };
      expect(accessTokenCallArgs.email).toBe('current@example.com');
    });

    it('should throw UnauthorizedException when the refresh token is expired', async () => {
      mockJwtService.verifyAsync.mockRejectedValueOnce(
        new Error('jwt expired'),
      );

      await expect(service.refreshTokens('expired.token')).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(service.refreshTokens('expired.token')).rejects.toThrow(
        'Invalid or expired refresh token',
      );
    });

    it('should throw UnauthorizedException for a completely invalid refresh token', async () => {
      mockJwtService.verifyAsync.mockRejectedValueOnce(
        new Error('invalid token'),
      );

      await expect(
        service.refreshTokens('garbage.token.value'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException when the user no longer exists in the DB (e.g. deleted)', async () => {
      const decoded = {
        id: 'deleted-uuid',
        email: 'gone@example.com',
        permissions: [],
        tokenVersion: 0,
      };

      mockJwtService.verifyAsync.mockResolvedValueOnce(decoded);
      mockUserService.getUserById.mockResolvedValueOnce(null);

      await expect(
        service.refreshTokens('valid.refresh.token'),
      ).rejects.toThrow(UnauthorizedException);
      await expect(mockUserService.getUserById).toHaveBeenCalledWith(
        'deleted-uuid',
      );
    });

    it('should throw UnauthorizedException when tokenVersion does not match (revoked session, e.g. after logout-all)', async () => {
      const user = buildUser({ tokenVersion: 2 });
      const decoded = {
        id: user.id,
        email: user.email,
        permissions: [],
        tokenVersion: 1,
      };

      mockJwtService.verifyAsync.mockResolvedValueOnce(decoded);
      mockUserService.getUserById.mockResolvedValueOnce(user);

      await expect(
        service.refreshTokens('stale.refresh.token'),
      ).rejects.toThrow(UnauthorizedException);
      await expect(
        service.refreshTokens('stale.refresh.token'),
      ).rejects.toThrow('Invalid or expired refresh token');
    });
  });

  // =========================================================================
  // revokeSessions
  // =========================================================================

  describe('revokeSessions', () => {
    it('should call userService.incrementTokenVersion with the given userId', async () => {
      mockUserService.incrementTokenVersion.mockResolvedValueOnce(undefined);

      await service.revokeSessions('uuid-1234');

      expect(mockUserService.incrementTokenVersion).toHaveBeenCalledWith(
        'uuid-1234',
      );
    });
  });

  // =========================================================================
  // getCookieOptions
  // =========================================================================

  describe('getCookieOptions', () => {
    it('should return accessTokenOptions and refreshTokenOptions objects', () => {
      const { accessTokenOptions, refreshTokenOptions } =
        service.getCookieOptions();

      expect(accessTokenOptions).toBeDefined();
      expect(refreshTokenOptions).toBeDefined();
    });

    it('both options should be httpOnly', () => {
      const { accessTokenOptions, refreshTokenOptions } =
        service.getCookieOptions();
      expect(accessTokenOptions.httpOnly).toBe(true);
      expect(refreshTokenOptions.httpOnly).toBe(true);
    });

    it('both options should have sameSite set to lax', () => {
      const { accessTokenOptions, refreshTokenOptions } =
        service.getCookieOptions();
      expect(accessTokenOptions.sameSite).toBe('lax');
      expect(refreshTokenOptions.sameSite).toBe('lax');
    });

    it('should set secure=false in non-production environments', () => {
      const { accessTokenOptions, refreshTokenOptions } =
        service.getCookieOptions();

      expect(accessTokenOptions.secure).toBe(false);
      expect(refreshTokenOptions.secure).toBe(false);
    });

    it('accessTokenOptions should have a positive maxAge in milliseconds', () => {
      const { accessTokenOptions } = service.getCookieOptions();
      expect(typeof accessTokenOptions.maxAge).toBe('number');
      expect(accessTokenOptions.maxAge).toBe(900_000);
    });

    it('refreshTokenOptions should have a larger maxAge than accessTokenOptions', () => {
      const { accessTokenOptions, refreshTokenOptions } =
        service.getCookieOptions();
      expect(refreshTokenOptions.maxAge!).toBeGreaterThan(
        accessTokenOptions.maxAge!,
      );
    });

    it('both options should have path set to "/"', () => {
      const { accessTokenOptions, refreshTokenOptions } =
        service.getCookieOptions();
      expect(accessTokenOptions.path).toBe('/');
      expect(refreshTokenOptions.path).toBe('/');
    });
  });

  // =========================================================================
  // register
  // =========================================================================

  describe('register', () => {
    it('should hash the password and create a new user, returning userId', async () => {
      mockUserService.getUserByEmail.mockResolvedValue(null);
      mockPermissionService.findPermission.mockResolvedValue({
        id: 'perm-1',
        name: 'USER',
        description: 'Standard user',
      });
      const savedUser = buildUser({ id: 'new-uuid' });
      mockUserService.createUser.mockResolvedValue(savedUser);

      const result = await service.register({
        email: 'new@example.com',
        password: 'Pass1234!',
      });

      expect(result.message).toBe('User registered successfully');
      expect(result.userId).toBe('new-uuid');
      expect(mockUserService.createUser).toHaveBeenCalledWith(
        expect.objectContaining({
          email: 'new@example.com',
          provider: 'local',
        }),
      );
    });

    it('should throw BadRequestException when the email is already registered', async () => {
      mockUserService.getUserByEmail.mockResolvedValue(buildUser());

      await expect(
        service.register({ email: 'test@example.com', password: 'Pass1234!' }),
      ).rejects.toThrow(BadRequestException);
      await expect(
        service.register({ email: 'test@example.com', password: 'Pass1234!' }),
      ).rejects.toThrow('User already registered');
    });
  });
});
