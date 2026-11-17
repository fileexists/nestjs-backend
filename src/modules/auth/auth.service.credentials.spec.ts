/**
 * D1/D2/D4/D5/D6 - registrazione e login (unit): risposta uniforme, bcrypt fittizio,
 * blocco per account, dispositivo riconosciuto, corse di registrazione, costo e re-hash.
 * Il comportamento sul database vero e' in test/db/d*.e2e-spec.ts.
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
const permissionService = { getRequired: jest.fn(), findPermission: jest.fn() };

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

describe('AuthService - credenziali', () => {
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
    mockLoginAttemptService.getLockedUntil.mockResolvedValue(null);
    service = await build();
  });

  describe('login - nessuna enumerazione (D1)', () => {
    const credentials = {
      email: 'mario@example.com',
      password: 'Wrong-Passw0rd!',
    };
    const messageOf = async (promise: Promise<unknown>) =>
      (await promise.catch((e: unknown) => e)) as UnauthorizedException;

    it('utente inesistente: confronta comunque con un hash bcrypt valido e risponde come per la password errata', async () => {
      userService.getUserByEmail.mockResolvedValue(null);

      const error = await messageOf(
        service.login(credentials, asResponse(buildResponse())),
      );

      expect(error).toBeInstanceOf(UnauthorizedException);
      expect(error.message).toBe('Invalid email or password');
      expect(bcryptCompare).toHaveBeenCalledTimes(1);
      const [, comparedHash] = bcryptCompare.mock.calls[0] as [string, string];
      expect(comparedHash).toMatch(/^\$2[aby]\$04\$/); // hash vero, stesso costo configurato
    });

    it('password errata, utente inesistente e account solo-Google: stesso status e stesso messaggio', async () => {
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

    it('anche senza password nel corpo si esegue un confronto bcrypt', async () => {
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

    it("l'hash fittizio si calcola una sola volta e si riusa", async () => {
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

    it('password corretta ma email non verificata: 403 (solo a chi conosce la password)', async () => {
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

  describe('login - blocco per account (D2)', () => {
    const ok = { email: 'mario@example.com', password: 'Correct-Passw0rd' };
    const bad = { email: 'mario@example.com', password: 'Wrong-Passw0rd!' };

    it('registra ogni errore (anche per account inesistenti)', async () => {
      userService.getUserByEmail.mockResolvedValue(null);
      await service
        .login(bad, asResponse(buildResponse()))
        .catch(() => undefined);
      expect(mockLoginAttemptService.recordFailure).toHaveBeenCalledWith(
        'mario@example.com',
      );
    });

    it("con account bloccato risponde 429 SENZA valutare la password e senza contare l'errore", async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: hash }),
      );
      mockLoginAttemptService.getLockedUntil.mockResolvedValue(
        new Date(Date.now() + 60_000),
      );

      const error = await service
        .login(ok, asResponse(buildResponse()))
        .catch((e: unknown) => e);

      expect(error).toBeInstanceOf(HttpException);
      expect((error as HttpException).getStatus()).toBe(429);
      expect(bcryptCompare).not.toHaveBeenCalled();
      expect(mockLoginAttemptService.recordFailure).not.toHaveBeenCalled();
    });

    it("il blocco vale anche per un'email inesistente (non rivela l'esistenza)", async () => {
      userService.getUserByEmail.mockResolvedValue(null);
      mockLoginAttemptService.getLockedUntil.mockResolvedValue(
        new Date(Date.now() + 60_000),
      );

      const error = await service
        .login(ok, asResponse(buildResponse()))
        .catch((e: unknown) => e);
      expect((error as HttpException).getStatus()).toBe(429);
    });

    it('un login riuscito azzera il contatore', async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: hash }),
      );
      await service.login(ok, asResponse(buildResponse()));
      expect(mockLoginAttemptService.reset).toHaveBeenCalledWith(
        'mario@example.com',
      );
    });

    describe('dispositivo riconosciuto', () => {
      const user = () => buildUser({ password: hash });
      const lock = () =>
        mockLoginAttemptService.getLockedUntil.mockResolvedValue(
          new Date(Date.now() + 60_000),
        );

      it('il proprietario con il cookie firmato entra anche durante il blocco', async () => {
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

      it("ma la password va comunque verificata: errata -> 401 e l'errore non estende il blocco", async () => {
        userService.getUserByEmail.mockResolvedValue(user());
        lock();
        const cookie = createTrustedDeviceCookie(JWT_SECRET, 'user-1', 0);

        await expect(
          service.login(bad, asResponse(buildResponse()), cookie),
        ).rejects.toBeInstanceOf(UnauthorizedException);
        expect(mockLoginAttemptService.recordFailure).not.toHaveBeenCalled();
      });

      it.each([
        [
          'cookie di un altro utente',
          () => createTrustedDeviceCookie(JWT_SECRET, 'someone-else', 0),
        ],
        [
          'tokenVersion cambiato (logout-all/reset)',
          () => createTrustedDeviceCookie(JWT_SECRET, 'user-1', 7),
        ],
        [
          'firmato con un altro segreto',
          () =>
            createTrustedDeviceCookie(
              'another-secret-0123456789abcdefghij',
              'user-1',
              0,
            ),
        ],
        [
          'scaduto',
          () =>
            createTrustedDeviceCookie(
              JWT_SECRET,
              'user-1',
              0,
              Date.now() - 400 * 86_400_000,
            ),
        ],
        ['spazzatura', () => 'garbage'],
      ])('%s: non sblocca (429)', async (_label, make) => {
        userService.getUserByEmail.mockResolvedValue(user());
        lock();

        const error = await service
          .login(ok, asResponse(buildResponse()), make())
          .catch((e: unknown) => e);
        expect((error as HttpException).getStatus()).toBe(429);
      });

      it('al login riuscito imposta il cookie del dispositivo (httpOnly, limitato a /api/auth)', async () => {
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

  describe('bcrypt: costo configurabile e re-hash (D6)', () => {
    it('hashPassword usa BCRYPT_ROUNDS', async () => {
      const result = await service.hashPassword('x');
      expect(bcrypt.getRounds(result)).toBe(ROUNDS);
    });

    it('il default e 12', async () => {
      const defaults = await build({ BCRYPT_ROUNDS: undefined });
      expect(bcrypt.getRounds(await defaults.hashPassword('x'))).toBe(12);
    });

    describe('re-hash trasparente al login', () => {
      const ok = { email: 'mario@example.com', password: 'Correct-Passw0rd' };

      it('rigenera un hash con costo inferiore e NON tocca tokenVersion', async () => {
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
        ['costo uguale', 4],
        ['costo superiore', 3],
      ])('non riscrive un hash con %s', async (_label, configured) => {
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

      it('con password sbagliata non rigenera nulla', async () => {
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

      it('se il re-hash fallisce il login riesce comunque', async () => {
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

  describe('register - risposta uniforme e corse (D1, D4, D5)', () => {
    const dto = { email: 'new@example.com', password: 'Correct-Passw0rd' };

    it("email nuova: crea l'utente con il permesso USER e invia la verifica", async () => {
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

    it('email gia registrata: stessa risposta, avviso al proprietario, NESSUNA modifica', async () => {
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

    it("l'hash bcrypt si calcola sempre, anche se l'email esiste (tempi uniformi)", async () => {
      userService.getUserByEmail.mockResolvedValue(
        buildUser({ password: hash }),
      );
      await service.register(dto);
      expect(bcryptHash).toHaveBeenCalledTimes(1);
    });

    it("chi perde la corsa (violazione di unicita) riceve la stessa risposta e il vincitore l'avviso, non un 500", async () => {
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

    it("un errore diverso dall'unicita viene propagato (non si nasconde un guasto)", async () => {
      userService.getUserByEmail.mockResolvedValue(null);
      userService.createUser.mockRejectedValue(new Error('connection lost'));
      await expect(service.register(dto)).rejects.toThrow('connection lost');
    });

    it('senza permesso USER risponde 503 prima di fare altro: nessun utente, nessun hash, nessuna email', async () => {
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

  describe('Google - corse e permesso mancante', () => {
    const google = { email: 'g@example.com', googleId: 'g-1' };

    it("due primi accessi contemporanei: chi perde la corsa prosegue con l'utente creato dall'altro", async () => {
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

    it('permesso USER mancante: 503 e nessun utente creato', async () => {
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
