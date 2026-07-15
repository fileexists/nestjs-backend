import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from './auth.guard';
import { AuthService } from '../../modules/auth/auth.service';
import { CookieOptions } from 'express';

function buildContext(options: {
  isPublic?: boolean;
  authHeader?: string;
  accessTokenCookie?: string;
  refreshTokenCookie?: string;
}): ExecutionContext {
  const {
    isPublic = false,
    authHeader,
    accessTokenCookie,
    refreshTokenCookie,
  } = options;

  const mockRequest: Record<string, unknown> = {
    headers: { authorization: authHeader },
    cookies: {
      ...(accessTokenCookie !== undefined
        ? { access_token: accessTokenCookie }
        : {}),
      ...(refreshTokenCookie !== undefined
        ? { refresh_token: refreshTokenCookie }
        : {}),
    },
    user: undefined,
  };

  const mockResponse = { cookie: jest.fn() };

  return {
    getHandler: jest.fn(),
    getClass: jest.fn(),
    switchToHttp: jest.fn().mockReturnValue({
      getRequest: jest.fn().mockReturnValue(mockRequest),
      getResponse: jest.fn().mockReturnValue(mockResponse),
    }),
    _mockRequest: mockRequest,
  } as unknown as ExecutionContext;
}

const mockJwtService: jest.Mocked<JwtService> = {
  verifyAsync: jest.fn(),
  sign: jest.fn(),
  verify: jest.fn(),
  decode: jest.fn(),
} as unknown as jest.Mocked<JwtService>;

const mockCookieOptions: {
  accessTokenOptions: CookieOptions;
  refreshTokenOptions: CookieOptions;
} = {
  accessTokenOptions: {
    httpOnly: false,
    secure: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 900_000,
  },
  refreshTokenOptions: {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 604_800_000,
  },
};

const mockAuthService: jest.Mocked<AuthService> = {
  refreshTokens: jest.fn(),
  verifyJwtToken: jest.fn(),
  getCookieOptions: jest.fn().mockReturnValue(mockCookieOptions),
  hashPassword: jest.fn(),
  comparePasswords: jest.fn(),
  generateJwtToken: jest.fn(),
  generateRefreshToken: jest.fn(),
} as unknown as jest.Mocked<AuthService>;

const mockReflector = { getAllAndOverride: jest.fn() };

const mockConfigService = { get: jest.fn((key: string) => process.env[key]) };

describe('AuthGuard', () => {
  let guard: AuthGuard;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthGuard,
        { provide: JwtService, useValue: mockJwtService },
        { provide: Reflector, useValue: mockReflector },
        { provide: AuthService, useValue: mockAuthService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    guard = module.get<AuthGuard>(AuthGuard);
    mockAuthService.getCookieOptions.mockReturnValue(mockCookieOptions);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('when the route is decorated with @Public()', () => {
    it('should allow access without any token', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(true);
      const ctx = buildContext({ isPublic: true });

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(mockJwtService.verifyAsync).not.toHaveBeenCalled();
    });
  });

  describe('when a valid Bearer token is in the Authorization header', () => {
    it('should verify the token, attach the payload to request.user, and return true', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(false);
      const payload = { id: 'uuid-1', email: 'a@b.com' };
      mockJwtService.verifyAsync.mockResolvedValue(payload);

      const ctx = buildContext({ authHeader: 'Bearer valid.token.here' });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(mockJwtService.verifyAsync).toHaveBeenCalledWith(
        'valid.token.here',
        expect.any(Object),
      );
    });
  });

  describe('when the access_token is in a cookie (no Authorization header)', () => {
    it('should extract it from cookies, verify, and allow access', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(false);
      const payload = { id: 'uuid-2', email: 'b@c.com' };
      mockJwtService.verifyAsync.mockResolvedValue(payload);

      const ctx = buildContext({ accessTokenCookie: 'cookie.access.token' });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(mockJwtService.verifyAsync).toHaveBeenCalledWith(
        'cookie.access.token',
        expect.anything(),
      );
    });
  });

  describe('when no access_token or refresh_token is present', () => {
    it('should throw UnauthorizedException', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(false);
      const ctx = buildContext({});

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('when the access token is expired and a refresh token is present', () => {
    it('should issue new tokens via refreshTokens and allow access', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(false);

      const expiredError = Object.assign(new Error('jwt expired'), {
        name: 'TokenExpiredError',
      });
      mockJwtService.verifyAsync.mockRejectedValue(expiredError);

      mockAuthService.refreshTokens.mockResolvedValue({
        token: 'new.access.token',
        refreshToken: 'new.refresh.token',
      });
      mockAuthService.verifyJwtToken.mockResolvedValue({
        id: 'uuid-3',
        email: 'c@d.com',
      });

      const ctx = buildContext({
        authHeader: 'Bearer expired.token',
        refreshTokenCookie: 'valid.refresh.token',
      });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(mockAuthService.refreshTokens).toHaveBeenCalledWith(
        'valid.refresh.token',
      );
    });
  });

  describe('when the access token is expired and there is no refresh token', () => {
    it('should throw UnauthorizedException', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(false);

      const expiredError = Object.assign(new Error('jwt expired'), {
        name: 'TokenExpiredError',
      });
      mockJwtService.verifyAsync.mockRejectedValue(expiredError);

      const ctx = buildContext({ accessTokenCookie: 'expired.access.token' });

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('when the access token signature is invalid', () => {
    it('should throw UnauthorizedException without attempting a refresh', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(false);

      const invalidError = Object.assign(new Error('invalid signature'), {
        name: 'JsonWebTokenError',
      });
      mockJwtService.verifyAsync.mockRejectedValue(invalidError);

      const ctx = buildContext({ authHeader: 'Bearer tampered.token' });

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(mockAuthService.refreshTokens).not.toHaveBeenCalled();
    });
  });

  describe('when both access and refresh tokens are invalid', () => {
    it('should throw UnauthorizedException after a failed token refresh attempt', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(false);

      const expiredError = Object.assign(new Error('jwt expired'), {
        name: 'TokenExpiredError',
      });
      mockJwtService.verifyAsync.mockRejectedValue(expiredError);
      mockAuthService.refreshTokens.mockRejectedValue(
        new UnauthorizedException('Invalid or expired refresh token'),
      );

      const ctx = buildContext({
        authHeader: 'Bearer expired.access',
        refreshTokenCookie: 'expired.refresh',
      });

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });
});
