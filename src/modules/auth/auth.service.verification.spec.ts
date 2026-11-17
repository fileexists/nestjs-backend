/**
 * A1 - verifica dell'email e collegamento Google (unit).
 * Il comportamento end-to-end sul database vero e' in test/db/a1-*.e2e-spec.ts.
 */
import { Test } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import type { Response } from 'express';
import { AuthService } from './auth.service';
import { GoogleAuthException } from './google-auth.exception';
import { UserService } from '../user/user.service';
import { PermissionService } from '../permission/permission.service';
import { User } from '../../common/entities/user.entity';
import {
  extraAuthProviders,
  mockAccountService,
  mockAuthTokenService,
  mockLoginAttemptService,
  resetAuthMocks,
} from './testing/auth-mocks';

const jwtService = { signAsync: jest.fn(), verifyAsync: jest.fn() };
const userService = {
  getUserByEmail: jest.fn(),
  getUserByGoogleId: jest.fn(),
  getUserById: jest.fn(),
  createUser: jest.fn(),
  updateUser: jest.fn(),
  claimUnverifiedForGoogle: jest.fn(),
};
const permissionService = { findPermission: jest.fn(), getRequired: jest.fn() };
const config: Record<string, string> = {
  JWT_SECRET: 'test-jwt-secret-minimum-32-chars!!',
  REFRESH_TOKEN_SECRET: 'test-refresh-secret-min-32chars!',
  JWT_EXPIRATION: '15m',
  REFRESH_TOKEN_EXPIRATION: '7d',
  NODE_ENV: 'test',
};

function buildUser(overrides: Partial<User> = {}): User {
  return Object.assign(new User(), {
    id: 'user-1',
    email: 'mario@example.com',
    password: undefined,
    googleId: undefined,
    provider: 'local',
    tokenVersion: 0,
    emailVerifiedAt: undefined,
    permissions: [],
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  });
}

function buildResponse(): jest.Mocked<
  Pick<Response, 'cookie' | 'json' | 'status'>
> {
  const res = { cookie: jest.fn(), json: jest.fn(), status: jest.fn() };
  res.status.mockReturnValue(res);
  return res;
}

describe('AuthService - verifica email (A1)', () => {
  let service: AuthService;
  let passwordHash: string;

  beforeAll(async () => {
    passwordHash = await bcrypt.hash('Correct-Passw0rd', 4);
  });

  beforeEach(async () => {
    jest.resetAllMocks();
    resetAuthMocks();
    jwtService.signAsync.mockResolvedValue('signed.jwt');
    mockLoginAttemptService.getLockedUntil.mockResolvedValue(null);
    userService.getUserByGoogleId.mockResolvedValue(null);
    permissionService.findPermission.mockResolvedValue({
      id: 'p1',
      name: 'USER',
    });
    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: JwtService, useValue: jwtService },
        { provide: ConfigService, useValue: { get: (k: string) => config[k] } },
        { provide: UserService, useValue: userService },
        { provide: PermissionService, useValue: permissionService },
        ...extraAuthProviders(),
      ],
    }).compile();
    service = module.get(AuthService);
  });

  describe('register', () => {
    it("crea l'utente NON verificato e invia l'email di verifica", async () => {
      userService.getUserByEmail.mockResolvedValue(null);
      const created = buildUser({ id: 'new-1', email: 'new@example.com' });
      userService.createUser.mockResolvedValue(created);

      await service.register({
        email: 'new@example.com',
        password: 'Correct-Passw0rd',
      });

      const data = (
        userService.createUser.mock.calls as unknown[][]
      )[0][0] as Partial<User>;
      expect(data.emailVerifiedAt).toBeUndefined();
      expect(mockAccountService.sendVerification).toHaveBeenCalledWith(created);
    });
  });

  describe('login', () => {
    it('con password corretta ma email NON verificata risponde 403 e non emette cookie', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: passwordHash, emailVerifiedAt: undefined }),
      );
      const res = buildResponse();

      await expect(
        service.login(
          { email: 'mario@example.com', password: 'Correct-Passw0rd' },
          res as unknown as Response,
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);
      expect(res.cookie).not.toHaveBeenCalled();
      expect(jwtService.signAsync).not.toHaveBeenCalled();
    });

    it("con password SBAGLIATA e email non verificata risponde 401 (non rivela lo stato dell'account)", async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: passwordHash, emailVerifiedAt: undefined }),
      );
      await expect(
        service.login(
          { email: 'mario@example.com', password: 'wrong-password' },
          buildResponse() as unknown as Response,
        ),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('con email verificata e password corretta emette i cookie', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: passwordHash, emailVerifiedAt: new Date() }),
      );
      const res = buildResponse();

      await service.login(
        { email: 'mario@example.com', password: 'Correct-Passw0rd' },
        res as unknown as Response,
      );

      expect(res.cookie).toHaveBeenCalledWith(
        'access_token',
        'signed.jwt',
        expect.any(Object),
      );
      expect(res.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'signed.jwt',
        expect.any(Object),
      );
    });
  });

  describe('handleGoogleCallback - collegamento sicuro', () => {
    const google = { email: 'mario@example.com', googleId: 'g-123' };

    it('crea un utente Google nuovo gia verificato', async () => {
      userService.getUserByEmail.mockResolvedValue(null);
      userService.createUser.mockResolvedValue(
        buildUser({ googleId: 'g-123', provider: 'google' }),
      );

      await service.handleGoogleCallback(
        google,
        buildResponse() as unknown as Response,
      );

      const data = (
        userService.createUser.mock.calls as unknown[][]
      )[0][0] as Partial<User>;
      expect(data).toEqual(
        expect.objectContaining({
          provider: 'google',
          googleId: 'g-123',
          emailVerifiedAt: expect.any(Date) as Date,
        }),
      );
    });

    it('su un account locale NON verificato rivendica l account: azzera la password e invalida sessioni e token', async () => {
      const attackerAccount = buildUser({
        password: 'attacker-hash',
        emailVerifiedAt: undefined,
      });
      const claimed = buildUser({
        password: undefined,
        googleId: 'g-123',
        provider: 'google',
        tokenVersion: 1,
        emailVerifiedAt: new Date(),
      });
      userService.getUserByEmail.mockResolvedValue(attackerAccount);
      userService.claimUnverifiedForGoogle.mockResolvedValue(claimed);

      await service.handleGoogleCallback(
        google,
        buildResponse() as unknown as Response,
      );

      expect(userService.claimUnverifiedForGoogle).toHaveBeenCalledWith(
        'user-1',
        'g-123',
      );
      expect(mockAuthTokenService.invalidateAll).toHaveBeenCalledWith('user-1');
      // nessun collegamento "normale" che lascerebbe la password dell'attaccante
      expect(userService.updateUser).not.toHaveBeenCalled();
    });

    it("se l'account e' stato verificato nel frattempo collega Google mantenendo la password", async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: 'hash', emailVerifiedAt: undefined }),
      );
      userService.claimUnverifiedForGoogle.mockResolvedValue(null);
      userService.getUserById.mockResolvedValue(
        buildUser({ password: 'hash', emailVerifiedAt: new Date() }),
      );
      userService.updateUser.mockResolvedValue(
        buildUser({
          password: 'hash',
          googleId: 'g-123',
          provider: 'combined',
        }),
      );

      await service.handleGoogleCallback(
        google,
        buildResponse() as unknown as Response,
      );

      expect(userService.updateUser).toHaveBeenCalledWith('user-1', {
        googleId: 'g-123',
        provider: 'combined',
      });
    });

    it('su un account locale VERIFICATO collega Google e mantiene la password (provider combined)', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: 'hash', emailVerifiedAt: new Date() }),
      );
      userService.updateUser.mockResolvedValue(
        buildUser({ googleId: 'g-123', provider: 'combined' }),
      );

      await service.handleGoogleCallback(
        google,
        buildResponse() as unknown as Response,
      );

      expect(userService.claimUnverifiedForGoogle).not.toHaveBeenCalled();
      expect(userService.updateUser).toHaveBeenCalledWith('user-1', {
        googleId: 'g-123',
        provider: 'combined',
      });
    });

    it('un utente gia combined non causa scritture inutili sul database a ogni login (C2)', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({
          password: 'hash',
          googleId: 'g-123',
          provider: 'combined',
          emailVerifiedAt: new Date(),
        }),
      );

      await service.handleGoogleCallback(
        google,
        buildResponse() as unknown as Response,
      );

      expect(userService.updateUser).not.toHaveBeenCalled();
      expect(userService.claimUnverifiedForGoogle).not.toHaveBeenCalled();
    });

    it('imposta i cookie di sessione dopo il collegamento', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({
          googleId: 'g-123',
          provider: 'google',
          emailVerifiedAt: new Date(),
        }),
      );
      const res = buildResponse();

      await service.handleGoogleCallback(google, res as unknown as Response);

      expect(res.cookie).toHaveBeenCalledWith(
        'access_token',
        'signed.jwt',
        expect.any(Object),
      );
    });
  });

  describe('handleGoogleCallback - confronto del googleId (B4)', () => {
    it('rifiuta con 401 account_conflict se l account ha GIA un googleId diverso', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({
          googleId: 'g-original',
          provider: 'google',
          emailVerifiedAt: new Date(),
        }),
      );
      const res = buildResponse();

      const error = await service
        .handleGoogleCallback(
          { email: 'mario@example.com', googleId: 'g-OTHER' },
          res as unknown as Response,
        )
        .catch((e: unknown) => e);

      expect(error).toBeInstanceOf(GoogleAuthException);
      expect((error as GoogleAuthException).code).toBe('account_conflict');
      expect((error as GoogleAuthException).getStatus()).toBe(401);
      expect(userService.updateUser).not.toHaveBeenCalled();
      expect(userService.claimUnverifiedForGoogle).not.toHaveBeenCalled();
      expect(res.cookie).not.toHaveBeenCalled();
    });

    it('non sovrascrive il googleId nemmeno per account con password (combined)', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({
          googleId: 'g-original',
          password: 'hash',
          provider: 'combined',
          emailVerifiedAt: new Date(),
        }),
      );

      await expect(
        service.handleGoogleCallback(
          { email: 'mario@example.com', googleId: 'g-OTHER' },
          buildResponse() as unknown as Response,
        ),
      ).rejects.toBeInstanceOf(GoogleAuthException);
      expect(userService.updateUser).not.toHaveBeenCalled();
    });

    it("cerca prima per googleId: se l utente esiste entra anche con un'email diversa, senza creare duplicati", async () => {
      userService.getUserByGoogleId.mockResolvedValue(
        buildUser({
          email: 'old@example.com',
          googleId: 'g-123',
          provider: 'google',
          emailVerifiedAt: new Date(),
        }),
      );
      const res = buildResponse();

      await service.handleGoogleCallback(
        { email: 'new@example.com', googleId: 'g-123' },
        res as unknown as Response,
      );

      expect(userService.getUserByEmail).not.toHaveBeenCalled();
      expect(userService.createUser).not.toHaveBeenCalled();
      expect(res.cookie).toHaveBeenCalledWith(
        'access_token',
        'signed.jwt',
        expect.any(Object),
      );
    });

    it('con lo stesso googleId in arrivo l account entra normalmente', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({
          googleId: 'g-123',
          provider: 'google',
          emailVerifiedAt: new Date(),
        }),
      );
      const res = buildResponse();

      await service.handleGoogleCallback(
        { email: 'mario@example.com', googleId: 'g-123' },
        res as unknown as Response,
      );

      expect(res.cookie).toHaveBeenCalledWith(
        'access_token',
        'signed.jwt',
        expect.any(Object),
      );
    });
  });
});
