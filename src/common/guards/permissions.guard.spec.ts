import { Test, TestingModule } from '@nestjs/testing';
import {
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PermissionsGuard } from './permissions.guard';
import { UserService } from '../../modules/user/user.service';
import { Permission } from '../entities/permission.entity';

function buildPermission(name: string): Permission {
  const p = new Permission();
  p.id = `perm-${name.toLowerCase()}`;
  p.name = name;
  p.description = `${name} role`;
  p.users = [];
  return p;
}

function buildContext(options: {
  userId?: string;
  required?: (string | string[])[] | undefined;
}): ExecutionContext {
  const { userId, required } = options;

  return {
    getHandler: jest.fn(),
    getClass: jest.fn(),
    switchToHttp: jest.fn().mockReturnValue({
      getRequest: jest.fn().mockReturnValue({
        user: userId ? { id: userId } : undefined,
      }),
    }),
    _required: required,
  } as unknown as ExecutionContext;
}

const mockUserService: jest.Mocked<Pick<UserService, 'getUserPermissions'>> = {
  getUserPermissions: jest.fn(),
};

const mockReflector = { getAllAndOverride: jest.fn() };

describe('PermissionsGuard', () => {
  let guard: PermissionsGuard;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PermissionsGuard,
        { provide: Reflector, useValue: mockReflector },
        { provide: UserService, useValue: mockUserService },
      ],
    }).compile();

    guard = module.get<PermissionsGuard>(PermissionsGuard);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('when no permissions are required on the route', () => {
    it('should allow access when reflector returns undefined', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(undefined);
      const ctx = buildContext({ userId: 'user-1' });

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(mockUserService.getUserPermissions).not.toHaveBeenCalled();
    });

    it('should allow access when reflector returns an empty array', async () => {
      mockReflector.getAllAndOverride.mockReturnValue([]);
      const ctx = buildContext({ userId: 'user-1' });

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
    });
  });

  describe('when required permissions exist but the user is not authenticated', () => {
    it('should throw UnauthorizedException when req.user is absent', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(['EDIT']);
      const ctx = buildContext({ userId: undefined });

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(guard.canActivate(ctx)).rejects.toThrow(
        'User is not authenticated.',
      );
    });
  });

  describe('when the user holds the ADMIN permission', () => {
    it('should allow access unconditionally regardless of what is required', async () => {
      mockReflector.getAllAndOverride.mockReturnValue([
        'DELETE_USERS',
        'MANAGE_*',
      ]);
      mockUserService.getUserPermissions.mockResolvedValue([
        buildPermission('ADMIN'),
      ]);

      const ctx = buildContext({ userId: 'admin-user-id' });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
    });
  });

  describe('when the user has the required permission', () => {
    it('should return true when the user holds a single required permission', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(['EDIT_POSTS']);
      mockUserService.getUserPermissions.mockResolvedValue([
        buildPermission('EDIT_POSTS'),
        buildPermission('VIEW_POSTS'),
      ]);

      const ctx = buildContext({ userId: 'user-1' });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
    });

    it('should return true when the user satisfies an AND-group (string[] inside the array)', async () => {
      mockReflector.getAllAndOverride.mockReturnValue([['READ', 'WRITE']]);
      mockUserService.getUserPermissions.mockResolvedValue([
        buildPermission('READ'),
        buildPermission('WRITE'),
      ]);

      const ctx = buildContext({ userId: 'user-1' });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
    });
  });

  describe('when the user lacks the required permission', () => {
    it('should throw ForbiddenException for a missing single permission', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(['DELETE_ALL']);
      mockUserService.getUserPermissions.mockResolvedValue([
        buildPermission('VIEW_POSTS'),
      ]);

      const ctx = buildContext({ userId: 'user-1' });

      await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
      await expect(guard.canActivate(ctx)).rejects.toThrow(
        'You do not have permission to access this resource.',
      );
    });

    it('should throw ForbiddenException when user meets only part of an AND-group', async () => {
      mockReflector.getAllAndOverride.mockReturnValue([['READ', 'WRITE']]);
      mockUserService.getUserPermissions.mockResolvedValue([
        buildPermission('READ'),
      ]);

      const ctx = buildContext({ userId: 'user-1' });

      await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
    });
  });

  describe('wildcard permission matching', () => {
    it('should grant access when the required permission has a wildcard that the user satisfies', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(['MANAGE_*']);
      mockUserService.getUserPermissions.mockResolvedValue([
        buildPermission('MANAGE_POSTS'),
      ]);

      const ctx = buildContext({ userId: 'user-1' });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
    });

    it('should deny access when the wildcard required permission does not match what the user holds', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(['DELETE_*']);
      mockUserService.getUserPermissions.mockResolvedValue([
        buildPermission('MANAGE_POSTS'),
      ]);

      const ctx = buildContext({ userId: 'user-1' });

      await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
    });
  });

  describe('when the user has no permissions assigned', () => {
    it('should throw ForbiddenException', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(['ANY_PERMISSION']);
      mockUserService.getUserPermissions.mockResolvedValue([]);

      const ctx = buildContext({ userId: 'user-no-perms' });

      await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
      await expect(guard.canActivate(ctx)).rejects.toThrow(
        'You do not have permission to access this resource.',
      );
    });
  });

  describe('case-insensitive permission matching', () => {
    it('should match "admin" (lowercase decorator default) against "ADMIN" stored in DB', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(['admin']);
      mockUserService.getUserPermissions.mockResolvedValue([
        buildPermission('ADMIN'),
      ]);

      const ctx = buildContext({ userId: 'user-1' });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
    });
  });

  describe('which decorator wins: method, then class', () => {
    it('asks the reflector for the handler first and the class second (getAllAndOverride)', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(undefined);
      const ctx = buildContext({ userId: 'user-1' });

      await guard.canActivate(ctx);

      expect(mockReflector.getAllAndOverride).toHaveBeenCalledWith(
        'permissions',
        [ctx.getHandler(), ctx.getClass()],
      );
    });
  });

  describe('wildcard: only * is special, everything else is literal', () => {
    const asUserWith = (...names: string[]) => {
      mockUserService.getUserPermissions.mockResolvedValue(
        names.map(buildPermission),
      );
      return buildContext({ userId: 'user-1' });
    };

    it.each([
      ['MANAGE_*', 'MANAGE_USERS'],
      ['MANAGE_*', 'MANAGE_'],
      ['*_READ', 'REPORTS_READ'],
      ['A*C', 'ABBBC'],
    ])('%s matches %s', async (required, held) => {
      mockReflector.getAllAndOverride.mockReturnValue([required]);

      await expect(guard.canActivate(asUserWith(held))).resolves.toBe(true);
    });

    it.each([
      // "." is a dot, not "any character"
      ['REPORT.*', 'REPORTX1'],
      ['REPORT.*', 'REPORT_1'],
      // "?", "+", "|" and "^" are not regex operators here
      ['USER?*', 'USERS'],
      ['A+*', 'AAAA'],
      ['READ|WRITE*', 'READ'],
      // anchored: the whole name has to match
      ['MANAGE_*', 'NOT_MANAGE_USERS'],
      ['*_READ', 'REPORTS_READ_ALL'],
    ])('%s does NOT match %s', async (required, held) => {
      mockReflector.getAllAndOverride.mockReturnValue([required]);

      await expect(guard.canActivate(asUserWith(held))).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('a dot in the required permission matches only a dot', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(['REPORT.*']);

      await expect(guard.canActivate(asUserWith('REPORT.DAILY'))).resolves.toBe(
        true,
      );
    });

    it.each(['A[*', 'A(*', 'A\\*', '(?<x>*', '*+'])(
      'a required permission with regex syntax (%s) is a plain denial, never a server error',
      async (required) => {
        mockReflector.getAllAndOverride.mockReturnValue([required]);

        await expect(
          guard.canActivate(asUserWith('SOMETHING')),
        ).rejects.toBeInstanceOf(ForbiddenException);
      },
    );

    it('a lone * is satisfied by any permission the user holds (and only by holding at least one)', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(['*']);

      await expect(guard.canActivate(asUserWith('ANYTHING'))).resolves.toBe(
        true,
      );

      mockUserService.getUserPermissions.mockResolvedValue([]);
      await expect(
        guard.canActivate(buildContext({ userId: 'user-1' })),
      ).rejects.toThrow(ForbiddenException);
    });

    it('a permission the user HOLDS is never a pattern', async () => {
      mockReflector.getAllAndOverride.mockReturnValue(['MANAGE_USERS']);

      await expect(guard.canActivate(asUserWith('MANAGE_*'))).rejects.toThrow(
        ForbiddenException,
      );
    });
  });
});
