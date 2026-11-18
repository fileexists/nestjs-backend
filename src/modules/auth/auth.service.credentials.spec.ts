/**
 * D1/D2/D4/D5/D6 - registration and login (unit): uniform response, dummy bcrypt,
 * per-account lock, recognized device, registration races, cost and re-hash.
 * The behaviour on the real database is in test/db/d*.e2e-spec.ts.
 */
import {
  ConflictException,
  ForbiddenException,
  HttpException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import * as bcrypt from 'bcrypt';
import type { Response } from 'express';
import { User } from '../../common/entities/user.entity';
import { PermissionService } from '../permission/permission.service';
import { UserService } from '../user/user.service';
import { AuthService, REGISTRATION_ACCEPTED_MESSAGE } from './auth.service';
import {
  extraAuthProviders,
  mockAccountService,
  mockLoginAttemptService,
  mockRefreshTokenService,
  resetAuthMocks,
} from './testing/auth-mocks';
import { createTrustedDeviceCookie } from './trusted-device';

jest.mock('bcrypt', () => {
  const actual = jest.requireActual<typeof import('bcrypt')>('bcrypt');
  return {
    ...actual,
    hash: jest
      .fn()
      .mockImplementation((...args: unknown[]) =>
        (actual.hash as (...a: unknown[]) => Promise<string>)(...args),
      ),
    compare: jest
      .fn()
      .mockImplementation((...args: unknown[]) =>
        (actual.compare as (...a: unknown[]) => Promise<boolean>)(...args),
      ),
  };
});

const JWT_SECRET = 'test-jwt-secret-minimum-32-chars!!';
const ROUNDS = 4;
const bcryptHash = bcrypt.hash as unknown as jest.Mock;
const bcryptCompare = bcrypt.compare as unknown as jest.Mock;

const jwtService = { signAsync: jest.fn(), verifyAsync: jest.fn() };
const userService = {
  getUserByEmail: jest.fn(),
  getUserByGoogleId: jest.fn(),
  getUserById: jest.fn(),
  createUser: jest.fn(),
  updateUser: jest.fn(),
  claimUnverifiedForGoogle: jest.fn(),
};
const permissionService = { getRequired: jest.fn() };

function buildUser(overrides: Partial<User> = {}): User {
  return Object.assign(new User(), {
    id: 'user-1',
    email: 'mario@example.com',
    password: undefined,
    provider: 'local',
    tokenVersion: 0,
    emailVerifiedAt: new Date(),
    permissions: [],
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  });
}

function buildResponse() {
  const res = { cookie: jest.fn(), json: jest.fn(), status: jest.fn() };
  res.status.mockReturnValue(res);
  return res;
}
const asResponse = (res: ReturnType<typeof buildResponse>) =>
  res as unknown as Response;

describe('AuthService - credentials', () => {
  let service: AuthService;
  let hash: string;
  const config: Record<string, unknown> = {
    JWT_SECRET,
    REFRESH_TOKEN_SECRET: 'test-refresh-secret-min-32chars!',
    JWT_EXPIRATION: '15m',
    REFRESH_TOKEN_EXPIRATION: '7d',
    NODE_ENV: 'test',
    BCRYPT_ROUNDS: ROUNDS,
  };

  async function build(overrides: Record<string, unknown> = {}) {
    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: JwtService, useValue: jwtService },
        {
          provide: ConfigService,
          useValue: { get: (k: string) => ({ ...config, ...overrides })[k] },
        },
        { provide: UserService, useValue: userService },
        { provide: PermissionService, useValue: permissionService },
        ...extraAuthProviders(),
      ],
    }).compile();
    return module.get(AuthService);
  }

  beforeAll(async () => {
    hash = await jest
      .requireActual<typeof import('bcrypt')>('bcrypt')
      .hash('Correct-Passw0rd', ROUNDS);
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    resetAuthMocks();
    jwtService.signAsync.mockResolvedValue('signed.jwt');
    permissionService.getRequired.mockResolvedValue({ id: 'p1', name: 'USER' });
    mockLoginAttemptService.registerAttempt.mockResolvedValue({
      locked: false,
    });
    service = await build();
  });

  describe('login - no enumeration (D1)', () => {
    const credentials = {
      email: 'mario@example.com',
      password: 'Wrong-Passw0rd!',
    };
    const messageOf = async (promise: Promise<unknown>) =>
      (await promise.catch((e: unknown) => e)) as UnauthorizedException;

    it('nonexistent user: still compares against a valid bcrypt hash and answers as for a wrong password', async () => {
      userService.getUserByEmail.mockResolvedValue(null);

      const error = await messageOf(
        service.login(credentials, asResponse(buildResponse())),
      );

      expect(error).toBeInstanceOf(UnauthorizedException);
      expect(error.message).toBe('Invalid email or password');
      expect(bcryptCompare).toHaveBeenCalledTimes(1);
      const [, comparedHash] = bcryptCompare.mock.calls[0] as [string, string];
      expect(comparedHash).toMatch(/^\$2[aby]\$04\$/); // real hash, same configured cost
    });

    it('wrong password, nonexistent user and Google-only account: same status and same message', async () => {
      const outcomes: UnauthorizedException[] = [];
      for (const user of [
        null,
        buildUser({ password: hash }),
        buildUser({ password: undefined, provider: 'google' }),
      ]) {
        userService.getUserByEmail.mockResolvedValue(user);
        outcomes.push(
          await messageOf(
            service.login(credentials, asResponse(buildResponse())),
          ),
        );
      }

      expect(new Set(outcomes.map((e) => e.getStatus()))).toEqual(
        new Set([401]),
      );
      expect(new Set(outcomes.map((e) => e.message))).toEqual(
        new Set(['Invalid email or password']),
      );
      expect(outcomes.map((e) => e.message).join()).not.toMatch(/google/i);
    });

    it('even without a password in the body a bcrypt comparison is made', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: hash }),
      );

      await expect(
        service.login(
          { email: 'mario@example.com' },
          asResponse(buildResponse()),
        ),
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(bcryptCompare).toHaveBeenCalledTimes(1);
    });

    describe('hash with a cost lower than BCRYPT_ROUNDS (earlier accounts)', () => {
      const wrong = { email: 'mario@example.com', password: 'Wrong-Passw0rd' };

      it('the work is evened out with dummy comparisons: timings do not reveal that the account exists', async () => {
        const stronger = await build({ BCRYPT_ROUNDS: 6 });
        userService.getUserByEmail.mockResolvedValue(
          buildUser({ password: hash }), // cost 4: 4 times faster than a cost 6 hash
        );

        await expect(
          stronger.login(wrong, asResponse(buildResponse())),
        ).rejects.toBeInstanceOf(UnauthorizedException);

        // 1 real compare + (2^(6-4) - 1) dummy ones = same work as a cost 6 hash
        expect(bcryptCompare).toHaveBeenCalledTimes(4);
      });

      it('with an equal or higher cost there is just one comparison', async () => {
        const looser = await build({ BCRYPT_ROUNDS: 4 });
        userService.getUserByEmail.mockResolvedValue(
          buildUser({ password: hash }),
        );

        await expect(
          looser.login(wrong, asResponse(buildResponse())),
        ).rejects.toBeInstanceOf(UnauthorizedException);

        expect(bcryptCompare).toHaveBeenCalledTimes(1);
      });

      it('an invalid hash in the database does not blow up the login', async () => {
        userService.getUserByEmail.mockResolvedValue(
          buildUser({ password: 'not-a-bcrypt-hash' }),
        );

        await expect(
          service.login(wrong, asResponse(buildResponse())),
        ).rejects.toBeInstanceOf(UnauthorizedException);
      });
    });

    it('the dummy hash is computed once and reused', async () => {
      userService.getUserByEmail.mockResolvedValue(null);

      await service
        .login(credentials, asResponse(buildResponse()))
        .catch(() => undefined);
      await service
        .login(credentials, asResponse(buildResponse()))
        .catch(() => undefined);

      expect(bcryptHash).toHaveBeenCalledTimes(1);
      expect(bcryptCompare).toHaveBeenCalledTimes(2);
    });

    it('correct password but unverified email: 403 (only to whoever knows the password)', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: hash, emailVerifiedAt: undefined }),
      );

      await expect(
        service.login(
          { email: 'mario@example.com', password: 'Correct-Passw0rd' },
          asResponse(buildResponse()),
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });
  });

  describe('login - per-account lock (D2)', () => {
    const ok = { email: 'mario@example.com', password: 'Correct-Passw0rd' };
    const bad = { email: 'mario@example.com', password: 'Wrong-Passw0rd!' };

    it('counts every attempt BEFORE checking the password (also for nonexistent accounts)', async () => {
      userService.getUserByEmail.mockResolvedValue(null);
      const order: string[] = [];
      mockLoginAttemptService.registerAttempt.mockImplementation(() => {
        order.push('count');
        return Promise.resolve({ locked: false });
      });
      bcryptCompare.mockImplementationOnce(() => {
        order.push('bcrypt');
        return Promise.resolve(false);
      });

      await service
        .login(bad, asResponse(buildResponse()))
        .catch(() => undefined);

      expect(mockLoginAttemptService.registerAttempt).toHaveBeenCalledWith(
        'mario@example.com',
      );
      expect(order).toEqual(['count', 'bcrypt']);
    });

    it('the wrong password does not record a second failure: the attempt is already counted', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: hash }),
      );

      await service
        .login(bad, asResponse(buildResponse()))
        .catch(() => undefined);

      expect(mockLoginAttemptService.registerAttempt).toHaveBeenCalledTimes(1);
    });

    it('with the account locked answers 429 WITHOUT evaluating the password', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: hash }),
      );
      mockLoginAttemptService.registerAttempt.mockResolvedValue({
        locked: true,
      });

      const error = await service
        .login(ok, asResponse(buildResponse()))
        .catch((e: unknown) => e);

      expect(error).toBeInstanceOf(HttpException);
      expect((error as HttpException).getStatus()).toBe(429);
      expect(bcryptCompare).not.toHaveBeenCalled();
    });

    it('the lock also applies to a nonexistent email (does not reveal existence)', async () => {
      userService.getUserByEmail.mockResolvedValue(null);
      mockLoginAttemptService.registerAttempt.mockResolvedValue({
        locked: true,
      });

      const error = await service
        .login(ok, asResponse(buildResponse()))
        .catch((e: unknown) => e);
      expect((error as HttpException).getStatus()).toBe(429);
    });

    it('a successful login resets the counter', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: hash }),
      );
      await service.login(ok, asResponse(buildResponse()));
      expect(mockLoginAttemptService.reset).toHaveBeenCalledWith(
        'mario@example.com',
      );
    });

    describe('recognized device', () => {
      const user = () => buildUser({ password: hash });
      const lock = () =>
        mockLoginAttemptService.registerAttempt.mockResolvedValue({
          locked: true,
        });

      it('the owner with the signed cookie gets in even during the lock', async () => {
        userService.getUserByEmail.mockResolvedValue(user());
        lock();
        const cookie = createTrustedDeviceCookie(JWT_SECRET, 'user-1', 0);

        const res = buildResponse();
        await service.login(ok, asResponse(res), cookie);

        expect(res.cookie).toHaveBeenCalledWith(
          'access_token',
          'signed.jwt',
          expect.any(Object),
        );
      });

      it('but the password must still be verified: wrong -> 401', async () => {
        userService.getUserByEmail.mockResolvedValue(user());
        lock();
        const cookie = createTrustedDeviceCookie(JWT_SECRET, 'user-1', 0);

        await expect(
          service.login(bad, asResponse(buildResponse()), cookie),
        ).rejects.toBeInstanceOf(UnauthorizedException);
      });

      it.each([
        [
          "another user's cookie",
          () => createTrustedDeviceCookie(JWT_SECRET, 'someone-else', 0),
        ],
        [
          'tokenVersion changed (logout-all/reset)',
          () => createTrustedDeviceCookie(JWT_SECRET, 'user-1', 7),
        ],
        [
          'signed with another secret',
          () =>
            createTrustedDeviceCookie(
              'another-secret-0123456789abcdefghij',
              'user-1',
              0,
            ),
        ],
        [
          'expired',
          () =>
            createTrustedDeviceCookie(
              JWT_SECRET,
              'user-1',
              0,
              Date.now() - 400 * 86_400_000,
            ),
        ],
        ['garbage', () => 'garbage'],
      ])('%s: does not unlock (429)', async (_label, make) => {
        userService.getUserByEmail.mockResolvedValue(user());
        lock();

        const error = await service
          .login(ok, asResponse(buildResponse()), make())
          .catch((e: unknown) => e);
        expect((error as HttpException).getStatus()).toBe(429);
      });

      it('on a successful login sets the device cookie (httpOnly, limited to /api/auth)', async () => {
        userService.getUserByEmail.mockResolvedValue(user());
        const res = buildResponse();

        await service.login(ok, asResponse(res));

        const call = res.cookie.mock.calls.find(
          (c: unknown[]) => c[0] === 'trusted_device',
        ) as [string, string, Record<string, unknown>];
        expect(call).toBeDefined();
        expect(call[2]).toMatchObject({
          httpOnly: true,
          sameSite: 'lax',
          path: '/api/auth',
        });
        expect(call[1].startsWith('user-1.0.')).toBe(true);
      });
    });
  });

  describe('bcrypt: configurable cost and re-hash (D6)', () => {
    it('hashPassword uses BCRYPT_ROUNDS', async () => {
      const result = await service.hashPassword('x');
      expect(bcrypt.getRounds(result)).toBe(ROUNDS);
    });

    it('il default e 12', async () => {
      const defaults = await build({ BCRYPT_ROUNDS: undefined });
      expect(bcrypt.getRounds(await defaults.hashPassword('x'))).toBe(12);
    });

    describe('transparent re-hash at login', () => {
      const ok = { email: 'mario@example.com', password: 'Correct-Passw0rd' };

      it('regenerates a hash with a lower cost and does NOT touch tokenVersion', async () => {
        const legacy = await jest
          .requireActual<typeof import('bcrypt')>('bcrypt')
          .hash('Correct-Passw0rd', 4);
        const stronger = await build({ BCRYPT_ROUNDS: 6 });
        userService.getUserByEmail.mockResolvedValue(
          buildUser({ password: legacy }),
        );

        await stronger.login(ok, asResponse(buildResponse()));

        const [, update] = userService.updateUser.mock.calls[0] as [
          string,
          { password: string; tokenVersion?: number },
        ];
        expect(bcrypt.getRounds(update.password)).toBe(6);
        expect(update.tokenVersion).toBeUndefined();
        expect(
          await jest
            .requireActual<typeof import('bcrypt')>('bcrypt')
            .compare('Correct-Passw0rd', update.password),
        ).toBe(true);
      });

      it.each([
        ['equal cost', 4],
        ['higher cost', 3],
      ])('does not rewrite a hash with %s', async (_label, configured) => {
        const current = await jest
          .requireActual<typeof import('bcrypt')>('bcrypt')
          .hash('Correct-Passw0rd', 4);
        const svc = await build({ BCRYPT_ROUNDS: configured });
        userService.getUserByEmail.mockResolvedValue(
          buildUser({ password: current }),
        );

        await svc.login(ok, asResponse(buildResponse()));

        expect(userService.updateUser).not.toHaveBeenCalled();
      });

      it('with a wrong password regenerates nothing', async () => {
        const legacy = await jest
          .requireActual<typeof import('bcrypt')>('bcrypt')
          .hash('Correct-Passw0rd', 4);
        const stronger = await build({ BCRYPT_ROUNDS: 6 });
        userService.getUserByEmail.mockResolvedValue(
          buildUser({ password: legacy }),
        );

        await stronger
          .login(
            { ...ok, password: 'Wrong-Passw0rd!' },
            asResponse(buildResponse()),
          )
          .catch(() => undefined);

        expect(userService.updateUser).not.toHaveBeenCalled();
      });

      it('if the re-hash fails the login still succeeds', async () => {
        const legacy = await jest
          .requireActual<typeof import('bcrypt')>('bcrypt')
          .hash('Correct-Passw0rd', 4);
        const stronger = await build({ BCRYPT_ROUNDS: 6 });
        userService.getUserByEmail.mockResolvedValue(
          buildUser({ password: legacy }),
        );
        userService.updateUser.mockRejectedValue(new Error('db down'));

        const res = buildResponse();
        await stronger.login(ok, asResponse(res));

        expect(res.cookie).toHaveBeenCalledWith(
          'access_token',
          'signed.jwt',
          expect.any(Object),
        );
      });
    });
  });

  describe('register - uniform response and races (D1, D4, D5)', () => {
    const dto = { email: 'new@example.com', password: 'Correct-Passw0rd' };

    it('new email: creates the user with the USER permission and sends the verification', async () => {
      userService.getUserByEmail.mockResolvedValue(null);
      const created = buildUser({ id: 'new-1', email: dto.email });
      userService.createUser.mockResolvedValue(created);

      const result = await service.register(dto);

      expect(result).toEqual({ message: REGISTRATION_ACCEPTED_MESSAGE });
      const data = (
        userService.createUser.mock.calls as unknown[][]
      )[0][0] as Partial<User>;
      expect(data.permissions).toEqual([{ id: 'p1', name: 'USER' }]);
      expect(data.provider).toBe('local');
      expect(bcrypt.getRounds(data.password!)).toBe(ROUNDS);
      expect(mockAccountService.sendVerification).toHaveBeenCalledWith(created);
      expect(mockAccountService.sendRegistrationNotice).not.toHaveBeenCalled();
    });

    it('already registered email: same response, notice to the owner, NO change', async () => {
      const existing = buildUser({ password: hash });
      userService.getUserByEmail.mockResolvedValue(existing);

      const result = await service.register(dto);

      expect(result).toEqual({ message: REGISTRATION_ACCEPTED_MESSAGE });
      expect(mockAccountService.sendRegistrationNotice).toHaveBeenCalledWith(
        existing,
      );
      expect(userService.createUser).not.toHaveBeenCalled();
      expect(userService.updateUser).not.toHaveBeenCalled();
      expect(mockAccountService.sendVerification).not.toHaveBeenCalled();
    });

    it('the bcrypt hash is always computed, even if the email exists (uniform timings)', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: hash }),
      );
      await service.register(dto);
      expect(bcryptHash).toHaveBeenCalledTimes(1);
    });

    it('whoever loses the race (uniqueness violation) gets the same response and the winner gets the notice, not a 500', async () => {
      const winner = buildUser({ id: 'winner' });
      userService.getUserByEmail
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(winner);
      userService.createUser.mockRejectedValue(
        new ConflictException('User already exists'),
      );

      const result = await service.register(dto);

      expect(result).toEqual({ message: REGISTRATION_ACCEPTED_MESSAGE });
      expect(mockAccountService.sendRegistrationNotice).toHaveBeenCalledWith(
        winner,
      );
      expect(mockAccountService.sendVerification).not.toHaveBeenCalled();
    });

    it('an error other than uniqueness is propagated (a failure is not hidden)', async () => {
      userService.getUserByEmail.mockResolvedValue(null);
      userService.createUser.mockRejectedValue(new Error('connection lost'));
      await expect(service.register(dto)).rejects.toThrow('connection lost');
    });

    it('without the USER permission answers 503 before doing anything else: no user, no hash, no email', async () => {
      permissionService.getRequired.mockRejectedValue(
        new ServiceUnavailableException('missing'),
      );

      await expect(service.register(dto)).rejects.toBeInstanceOf(
        ServiceUnavailableException,
      );
      expect(userService.createUser).not.toHaveBeenCalled();
      expect(bcryptHash).not.toHaveBeenCalled();
      expect(mockAccountService.sendVerification).not.toHaveBeenCalled();
    });
  });

  describe('session: access and refresh token of the same family', () => {
    const familiesSigned = () =>
      (jwtService.signAsync.mock.calls as [{ fid: string }][]).map(
        ([payload]) => payload.fid,
      );

    it('login: a new family, the same in both tokens and in the recorded refresh token', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: hash }),
      );

      await service.login(
        { email: 'mario@example.com', password: 'Correct-Passw0rd' },
        asResponse(buildResponse()),
      );

      const [access, refresh] = familiesSigned();
      expect(access).toEqual(expect.any(String));
      expect(refresh).toBe(access);
      expect(mockRefreshTokenService.create).toHaveBeenCalledWith(
        expect.objectContaining({ familyId: access }),
      );
    });

    it('two consecutive logins open two different families (one per device)', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: hash }),
      );
      const credentials = {
        email: 'mario@example.com',
        password: 'Correct-Passw0rd',
      };

      await service.login(credentials, asResponse(buildResponse()));
      await service.login(credentials, asResponse(buildResponse()));

      const [first, , second] = familiesSigned();
      expect(first).not.toBe(second);
    });

    it('Google: same family in both tokens', async () => {
      userService.getUserByGoogleId.mockResolvedValue(
        buildUser({ googleId: 'g-1', provider: 'google' }),
      );

      await service.handleGoogleCallback(
        { email: 'mario@example.com', googleId: 'g-1' },
        asResponse(buildResponse()),
      );

      const [access, refresh] = familiesSigned();
      expect(access).toEqual(expect.any(String));
      expect(refresh).toBe(access);
    });
  });

  describe('Google - races and missing permission', () => {
    const google = { email: 'g@example.com', googleId: 'g-1' };

    it('two simultaneous first logins: whoever loses the race carries on with the user created by the other', async () => {
      userService.getUserByGoogleId
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(
          buildUser({ googleId: 'g-1', provider: 'google' }),
        );
      userService.getUserByEmail.mockResolvedValue(null);
      userService.createUser.mockRejectedValue(
        new ConflictException('User already exists'),
      );
      const res = buildResponse();

      await service.handleGoogleCallback(google, asResponse(res));

      expect(res.cookie).toHaveBeenCalledWith(
        'access_token',
        'signed.jwt',
        expect.any(Object),
      );
    });

    it('USER permission missing: 503 and no user created', async () => {
      userService.getUserByGoogleId.mockResolvedValue(null);
      userService.getUserByEmail.mockResolvedValue(null);
      permissionService.getRequired.mockRejectedValue(
        new ServiceUnavailableException('missing'),
      );

      await expect(
        service.handleGoogleCallback(google, asResponse(buildResponse())),
      ).rejects.toBeInstanceOf(ServiceUnavailableException);
      expect(userService.createUser).not.toHaveBeenCalled();
    });
  });
});
