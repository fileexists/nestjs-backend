import { UnauthorizedException } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { instanceToPlain } from 'class-transformer';
import { Permission } from '../../common/entities/permission.entity';
import { User } from '../../common/entities/user.entity';
import { UserController } from './user.controller';
import { UserService } from './user.service';

function buildUser(): User {
  const permission = Object.assign(new Permission(), {
    id: 'perm-1',
    name: 'USER',
    description: 'Basic user access',
    users: [{ id: 'other-user', password: 'leak-me' }] as User[],
  });
  return Object.assign(new User(), {
    id: 'user-1',
    email: 'mario@example.com',
    password: '$2b$12$secret-hash',
    googleId: 'google-sub-123',
    provider: 'combined',
    tokenVersion: 7,
    emailVerifiedAt: new Date('2024-01-01T00:00:00.000Z'),
    createdAt: new Date('2024-01-01T00:00:00.000Z'),
    updatedAt: new Date('2024-01-02T00:00:00.000Z'),
    permissions: [permission],
  });
}

describe('UserController (D3)', () => {
  const userService = { getUserById: jest.fn() };
  let controller: UserController;

  beforeEach(async () => {
    jest.resetAllMocks();
    const module = await Test.createTestingModule({
      controllers: [UserController],
      providers: [{ provide: UserService, useValue: userService }],
    }).compile();
    controller = module.get(UserController);
  });

  const me = () =>
    controller.getCurrentUser({ user: { id: 'user-1' } } as never);

  it('restituisce SOLO i campi della whitelist', async () => {
    userService.getUserById.mockResolvedValue(buildUser());

    const dto = await me();

    expect(Object.keys(instanceToPlain(dto)).sort()).toEqual([
      'createdAt',
      'email',
      'emailVerified',
      'id',
      'permissions',
      'provider',
      'updatedAt',
    ]);
  });

  it.each(['tokenVersion', 'password', 'googleId', 'emailVerifiedAt'])(
    'nessun campo interno: "%s" non compare nel JSON finale (nemmeno annidato)',
    async (field) => {
      userService.getUserById.mockResolvedValue(buildUser());

      const json = JSON.stringify(instanceToPlain(await me()));

      expect(json).not.toContain(`"${field}"`);
      expect(json).not.toContain('google-sub-123');
      expect(json).not.toContain('secret-hash');
      expect(json).not.toContain('leak-me');
    },
  );

  it('i permessi espongono solo id, name e description', async () => {
    userService.getUserById.mockResolvedValue(buildUser());

    const plain = instanceToPlain(await me()) as {
      permissions: Record<string, unknown>[];
    };

    expect(Object.keys(plain.permissions[0]).sort()).toEqual([
      'description',
      'id',
      'name',
    ]);
  });

  it('emailVerified e un booleano calcolato da emailVerifiedAt', async () => {
    userService.getUserById.mockResolvedValue(buildUser());
    expect(
      (instanceToPlain(await me()) as { emailVerified: boolean }).emailVerified,
    ).toBe(true);

    userService.getUserById.mockResolvedValue(
      Object.assign(buildUser(), { emailVerifiedAt: null }),
    );
    expect(
      (instanceToPlain(await me()) as { emailVerified: boolean }).emailVerified,
    ).toBe(false);
  });

  it("l'entita User serializzata direttamente (come fa il serializzatore globale) esclude i campi interni: difesa in profondita", () => {
    const plain = instanceToPlain(buildUser());

    expect(plain).not.toHaveProperty('password');
    expect(plain).not.toHaveProperty('tokenVersion');
    expect(plain).not.toHaveProperty('googleId');
  });

  it('senza utente autenticato o utente inesistente: 401', async () => {
    await expect(controller.getCurrentUser({} as never)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    userService.getUserById.mockResolvedValue(null);
    await expect(me()).rejects.toBeInstanceOf(UnauthorizedException);
  });
});
