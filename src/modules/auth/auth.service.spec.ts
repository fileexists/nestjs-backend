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
import {
  extraAuthProviders,
  mockRefreshTokenService,
  resetAuthMocks,
} from './testing/auth-mocks';

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
  getAuthState: jest.fn(),
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
        ...extraAuthProviders(),
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  afterEach(() => {
    jest.clearAllMocks();
    resetAuthMocks();
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
    it('should sign id, email AND tokenVersion with the access-token secret and expiry', async () => {
      const user = buildUser({ tokenVersion: 4 });
      mockJwtService.signAsync.mockResolvedValue('signed.jwt.token');

      const token = await service.generateJwtToken(user);

      expect(mockJwtService.signAsync).toHaveBeenCalledTimes(1);
      expect(mockJwtService.signAsync).toHaveBeenCalledWith(
        { id: user.id, email: user.email, tokenVersion: 4 },
        expect.objectContaining({
          secret: expect.any(String) as string,
          expiresIn: '15m',
        }),
      );
      expect(token).toBe('signed.jwt.token');
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
    it('should sign a refresh token with a unique jti and a family id, using the refresh secret and expiry', async () => {
      const user = buildUser({ tokenVersion: 3 });
      mockJwtService.signAsync.mockResolvedValue('refresh.token.value');

      const token = await service.generateRefreshToken(user);

      expect(mockJwtService.signAsync).toHaveBeenCalledWith(
        {
          id: user.id,
          email: user.email,
          tokenVersion: 3,
          fid: expect.any(String) as string,
        },
        expect.objectContaining({
          expiresIn: '7d',
          jwtid: expect.any(String) as string,
        }),
      );
      expect(token).toBe('refresh.token.value');
    });

    it('should register the token (jti, family, expiry) in the refresh_tokens store', async () => {
      const user = buildUser();
      mockJwtService.signAsync.mockResolvedValue('refresh.token');
      const before = Date.now();

      await service.generateRefreshToken(user);

      const [payload, options] = mockJwtService.signAsync.mock.calls[0] as [
        { fid: string },
        { jwtid: string },
      ];
      expect(mockRefreshTokenService.create).toHaveBeenCalledTimes(1);
      const stored = (
        mockRefreshTokenService.create.mock.calls as unknown[][]
      )[0][0] as {
        userId: string;
        jti: string;
        familyId: string;
        expiresAt: Date;
      };
      expect(stored.userId).toBe(user.id);
      expect(stored.jti).toBe(options.jwtid);
      expect(stored.familyId).toBe(payload.fid);
      expect(stored.expiresAt.getTime()).toBeGreaterThanOrEqual(
        before + 7 * 86_400_000,
      );
    });

    it('should start a NEW family at login and generate a different jti every time', async () => {
      mockJwtService.signAsync.mockResolvedValue('t');

      await service.generateRefreshToken(buildUser());
      await service.generateRefreshToken(buildUser());

      const [a, b] = mockRefreshTokenService.create.mock.calls.map(
        (c: unknown[]) => c[0] as { jti: string; familyId: string },
      );
      expect(a.jti).not.toBe(b.jti);
      expect(a.familyId).not.toBe(b.familyId);
    });

    it('should keep the given family id when rotating', async () => {
      mockJwtService.signAsync.mockResolvedValue('t');

      await service.generateRefreshToken(buildUser(), 'family-xyz');

      expect(mockRefreshTokenService.create).toHaveBeenCalledWith(
        expect.objectContaining({ familyId: 'family-xyz' }),
      );
      expect(mockJwtService.signAsync).toHaveBeenCalledWith(
        expect.objectContaining({ fid: 'family-xyz' }),
        expect.anything(),
      );
    });

    it('should embed tokenVersion in the access token payload (session revocation is checked per request)', async () => {
      const user = buildUser({ tokenVersion: 5 });
      mockJwtService.signAsync.mockResolvedValue('access.token');

      await service.generateJwtToken(user);

      const callArgs = mockJwtService.signAsync.mock.calls[0][0] as Record<
        string,
        unknown
      >;
      expect(callArgs.tokenVersion).toBe(5);
    });
  });

  // =========================================================================
  // verifyJwtToken / assertSessionCurrent
  // =========================================================================

  describe('verifyJwtToken', () => {
    it('should return the decoded payload when the token is valid and its session is current', async () => {
      const payload = {
        id: 'uuid-1234',
        email: 'test@example.com',
        tokenVersion: 0,
      };
      mockJwtService.verifyAsync.mockResolvedValue(payload);
      mockUserService.getAuthState.mockResolvedValue({ tokenVersion: 0 });

      await expect(service.verifyJwtToken('valid.jwt.token')).resolves.toEqual(
        payload,
      );
    });

    it('should throw UnauthorizedException when the token carries a stale tokenVersion', async () => {
      mockJwtService.verifyAsync.mockResolvedValue({
        id: 'uuid-1234',
        tokenVersion: 0,
      });
      mockUserService.getAuthState.mockResolvedValue({ tokenVersion: 1 });

      await expect(service.verifyJwtToken('stale.jwt')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException when jwtService.verifyAsync throws', async () => {
      mockJwtService.verifyAsync.mockRejectedValue(new Error('jwt expired'));

      await expect(service.verifyJwtToken('expired.jwt.token')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException for a completely malformed token string', async () => {
      mockJwtService.verifyAsync.mockRejectedValue(new Error('jwt malformed'));

      await expect(service.verifyJwtToken('not-a-jwt')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException when no token is provided', async () => {
      await expect(service.verifyJwtToken(undefined)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('assertSessionCurrent', () => {
    it('accepts a payload whose tokenVersion matches the database', async () => {
      mockUserService.getAuthState.mockResolvedValue({ tokenVersion: 2 });
      await expect(
        service.assertSessionCurrent({ id: 'u1', tokenVersion: 2 }),
      ).resolves.toBeUndefined();
    });

    it.each([
      [
        'tokenVersion diverso',
        { id: 'u1', tokenVersion: 1 },
        { tokenVersion: 2 },
      ],
      ['utente cancellato', { id: 'u1', tokenVersion: 0 }, null],
      [
        'token senza tokenVersion (emesso prima della modifica)',
        { id: 'u1' },
        { tokenVersion: 0 },
      ],
    ])('rejects: %s', async (_label, payload, state) => {
      mockUserService.getAuthState.mockResolvedValue(state);
      await expect(
        service.assertSessionCurrent(payload),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('rejects a payload without id without touching the database', async () => {
      await expect(service.assertSessionCurrent({})).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
      expect(mockUserService.getAuthState).not.toHaveBeenCalled();
    });
  });

  // =========================================================================
  // refreshTokens (rotazione + reuse detection)
  // =========================================================================

  describe('refreshTokens', () => {
    const decoded = {
      id: 'uuid-1234',
      email: 'test@example.com',
      tokenVersion: 0,
      jti: 'jti-1',
      fid: 'family-1',
    };
    const storedToken = (overrides: Record<string, unknown> = {}) => ({
      id: 'row-1',
      userId: 'uuid-1234',
      familyId: 'family-1',
      usedAt: new Date(),
      ...overrides,
    });

    beforeEach(() => {
      mockJwtService.verifyAsync.mockResolvedValue(decoded);
      mockJwtService.signAsync.mockResolvedValue('new.token');
      mockRefreshTokenService.rotate.mockResolvedValue({
        status: 'rotated',
        token: storedToken(),
      });
    });

    it('rotates: marks the old jti as used and issues a new pair in the SAME family', async () => {
      mockUserService.getUserById.mockResolvedValue(buildUser());

      const result = await service.refreshTokens('old.refresh.token');

      expect(result).toEqual({ token: 'new.token', refreshToken: 'new.token' });
      expect(mockRefreshTokenService.rotate).toHaveBeenCalledWith('jti-1');
      expect(mockRefreshTokenService.create).toHaveBeenCalledWith(
        expect.objectContaining({ familyId: 'family-1', userId: 'uuid-1234' }),
      );
    });

    it('signs the new tokens from the freshly loaded user, not the stale decoded payload', async () => {
      mockUserService.getUserById.mockResolvedValue(
        buildUser({ email: 'changed@example.com' }),
      );

      await service.refreshTokens('old.refresh.token');

      const payloads = mockJwtService.signAsync.mock.calls.map(
        (c) => c[0] as { email: string },
      );
      expect(payloads.every((p) => p.email === 'changed@example.com')).toBe(
        true,
      );
    });

    it('rejects a token that was already used (reuse): revokes the family AND invalidates the sessions', async () => {
      mockRefreshTokenService.rotate.mockResolvedValue({
        status: 'reused',
        token: storedToken({ usedAt: new Date(Date.now() - 60_000) }),
      });

      await expect(
        service.refreshTokens('stolen.token'),
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(mockRefreshTokenService.revokeFamily).toHaveBeenCalledWith(
        'family-1',
      );
      expect(mockUserService.incrementTokenVersion).toHaveBeenCalledWith(
        'uuid-1234',
      );
      expect(mockRefreshTokenService.create).not.toHaveBeenCalled();
    });

    it.each(['invalid'])(
      'rejects an unknown/revoked/expired token (%s) without touching the family',
      async (status) => {
        mockRefreshTokenService.rotate.mockResolvedValue({ status });

        await expect(service.refreshTokens('x')).rejects.toBeInstanceOf(
          UnauthorizedException,
        );
        expect(mockRefreshTokenService.revokeFamily).not.toHaveBeenCalled();
        expect(mockUserService.incrementTokenVersion).not.toHaveBeenCalled();
      },
    );

    it.each([
      ['senza jti', { ...decoded, jti: undefined }],
      ['senza fid', { ...decoded, fid: undefined }],
      ['senza id', { ...decoded, id: undefined }],
    ])(
      'rejects a legacy/forged refresh token %s before hitting the store',
      async (_label, payload) => {
        mockJwtService.verifyAsync.mockResolvedValue(payload);

        await expect(service.refreshTokens('legacy')).rejects.toBeInstanceOf(
          UnauthorizedException,
        );
        expect(mockRefreshTokenService.rotate).not.toHaveBeenCalled();
      },
    );

    it('throws UnauthorizedException when the refresh token is expired or invalid (bad signature)', async () => {
      mockJwtService.verifyAsync.mockRejectedValue(new Error('jwt expired'));

      await expect(service.refreshTokens('expired')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
      expect(mockRefreshTokenService.rotate).not.toHaveBeenCalled();
    });

    it('throws UnauthorizedException when the user no longer exists', async () => {
      mockUserService.getUserById.mockResolvedValue(null);

      await expect(service.refreshTokens('t')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('throws UnauthorizedException when tokenVersion does not match (revoked session)', async () => {
      mockUserService.getUserById.mockResolvedValue(
        buildUser({ tokenVersion: 1 }),
      );

      await expect(service.refreshTokens('t')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
      expect(mockRefreshTokenService.create).not.toHaveBeenCalled();
    });

    it('never leaks infrastructure errors as 500: any failure is a 401', async () => {
      mockRefreshTokenService.rotate.mockRejectedValue(new Error('db down'));

      await expect(service.refreshTokens('t')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });
  });

  // =========================================================================
  // logout / revokeSessions
  // =========================================================================

  describe('logout', () => {
    it('revokes the family of the presented refresh token', async () => {
      mockJwtService.verifyAsync.mockResolvedValue({
        id: 'u1',
        fid: 'family-9',
      });

      await service.logout('refresh.token');

      expect(mockRefreshTokenService.revokeFamily).toHaveBeenCalledWith(
        'family-9',
      );
      expect(mockJwtService.verifyAsync).toHaveBeenCalledWith(
        'refresh.token',
        expect.objectContaining({ ignoreExpiration: true }),
      );
    });

    it('does nothing (and does not throw) without a cookie', async () => {
      await expect(service.logout(undefined)).resolves.toBeUndefined();
      expect(mockRefreshTokenService.revokeFamily).not.toHaveBeenCalled();
    });

    it('does not throw for a forged/garbage cookie and revokes nothing', async () => {
      mockJwtService.verifyAsync.mockRejectedValue(
        new Error('invalid signature'),
      );

      await expect(service.logout('garbage')).resolves.toBeUndefined();
      expect(mockRefreshTokenService.revokeFamily).not.toHaveBeenCalled();
    });
  });

  describe('revokeSessions', () => {
    it('bumps tokenVersion (kills access tokens) and revokes every refresh token of the user', async () => {
      mockUserService.incrementTokenVersion.mockResolvedValue(undefined);

      await service.revokeSessions('uuid-1234');

      expect(mockUserService.incrementTokenVersion).toHaveBeenCalledWith(
        'uuid-1234',
      );
      expect(mockRefreshTokenService.revokeAllForUser).toHaveBeenCalledWith(
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
