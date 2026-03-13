import { Test, TestingModule } from '@nestjs/testing';
import {
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PermissionsGuard } from './permissions.guard';
import { UserService } from '../../features/user/user.service';
import { Permission } from '../../database/permission.entity';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildPermission(name: string): Permission {
  const p = new Permission();
  p.id = `perm-${name.toLowerCase()}`;
  p.name = name;
  p.description = `${name} role`;
  p.users = [];
  return p;
}

/**
 * Builds a minimal mock ExecutionContext.
 * @param userId    – id surfaced on req.user (undefined = unauthenticated)
 * @param required  – value returned by reflector.get('permissions', …)
 */
function buildContext(options: {
  userId?: string;
  required?: (string | string[])[] | undefined;
}): ExecutionContext {
  const { userId, required } = options;

  return {
    getHandler: jest.fn(),
    switchToHttp: jest.fn().mockReturnValue({
      getRequest: jest.fn().mockReturnValue({
        user: userId ? { id: userId } : undefined,
      }),
    }),
    _required: required,
  } as unknown as ExecutionContext;
}

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockUserService: jest.Mocked<Pick<UserService, 'getUserPermissions'>> = {
  getUserPermissions: jest.fn(),
};

const mockReflector = {
  get: jest.fn(),
};

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

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

  // -------------------------------------------------------------------------
  // No required permissions
  // -------------------------------------------------------------------------

  describe('when no permissions are required on the route', () => {
    it('should allow access when reflector returns undefined', async () => {
      mockReflector.get.mockReturnValue(undefined);
      const ctx = buildContext({ userId: 'user-1' });

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(mockUserService.getUserPermissions).not.toHaveBeenCalled();
    });

    it('should allow access when reflector returns an empty array', async () => {
      mockReflector.get.mockReturnValue([]);
      const ctx = buildContext({ userId: 'user-1' });

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Unauthenticated request
  // -------------------------------------------------------------------------

  describe('when required permissions exist but the user is not authenticated', () => {
    it('should throw UnauthorizedException when req.user is absent', async () => {
      mockReflector.get.mockReturnValue(['EDIT']);
      const ctx = buildContext({ userId: undefined });

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      await expect(guard.canActivate(ctx)).rejects.toThrow('User is not authenticated.');
    });
  });

  // -------------------------------------------------------------------------
  // ADMIN bypass
  // -------------------------------------------------------------------------

  describe('when the user holds the ADMIN permission', () => {
    it('should allow access unconditionally regardless of what is required', async () => {
      mockReflector.get.mockReturnValue(['DELETE_USERS', 'MANAGE_*']);
      mockUserService.getUserPermissions.mockResolvedValue([buildPermission('ADMIN')]);

      const ctx = buildContext({ userId: 'admin-user-id' });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Sufficient regular permissions
  // -------------------------------------------------------------------------

  describe('when the user has the required permission', () => {
    it('should return true when the user holds a single required permission', async () => {
      mockReflector.get.mockReturnValue(['EDIT_POSTS']);
      mockUserService.getUserPermissions.mockResolvedValue([
        buildPermission('EDIT_POSTS'),
        buildPermission('VIEW_POSTS'),
      ]);

      const ctx = buildContext({ userId: 'user-1' });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
    });

    it('should return true when the user satisfies an AND-group (string[] inside the array)', async () => {
      // AND-group: user must have BOTH 'READ' and 'WRITE'
      mockReflector.get.mockReturnValue([['READ', 'WRITE']]);
      mockUserService.getUserPermissions.mockResolvedValue([
        buildPermission('READ'),
        buildPermission('WRITE'),
      ]);

      const ctx = buildContext({ userId: 'user-1' });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Insufficient permissions
  // -------------------------------------------------------------------------

  describe('when the user lacks the required permission', () => {
    it('should throw ForbiddenException for a missing single permission', async () => {
      mockReflector.get.mockReturnValue(['DELETE_ALL']);
      mockUserService.getUserPermissions.mockResolvedValue([buildPermission('VIEW_POSTS')]);

      const ctx = buildContext({ userId: 'user-1' });

      await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
      await expect(guard.canActivate(ctx)).rejects.toThrow(
        'You do not have permission to access this resource.',
      );
    });

    it('should throw ForbiddenException when user meets only part of an AND-group', async () => {
      mockReflector.get.mockReturnValue([['READ', 'WRITE']]);
      // Only holds READ, missing WRITE
      mockUserService.getUserPermissions.mockResolvedValue([buildPermission('READ')]);

      const ctx = buildContext({ userId: 'user-1' });

      await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
    });
  });

  // -------------------------------------------------------------------------
  // Wildcard permissions
  // -------------------------------------------------------------------------

  describe('wildcard permission matching', () => {
    it('should grant access when the required permission has a wildcard that the user satisfies', async () => {
      // Route decorated with @Permissions('MANAGE_*');
      // user holds 'MANAGE_POSTS' which matches the regex ^MANAGE_.*$
      mockReflector.get.mockReturnValue(['MANAGE_*']);
      mockUserService.getUserPermissions.mockResolvedValue([buildPermission('MANAGE_POSTS')]);

      const ctx = buildContext({ userId: 'user-1' });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
    });

    it('should deny access when the wildcard required permission does not match what the user holds', async () => {
      // Route decorated with @Permissions('DELETE_*');
      // user only holds 'MANAGE_POSTS' which does NOT match ^DELETE_.*$
      mockReflector.get.mockReturnValue(['DELETE_*']);
      mockUserService.getUserPermissions.mockResolvedValue([buildPermission('MANAGE_POSTS')]);

      const ctx = buildContext({ userId: 'user-1' });

      await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
    });
  });

  // -------------------------------------------------------------------------
  // Empty permissions on the user
  // -------------------------------------------------------------------------

  describe('when the user has no permissions assigned', () => {
    it('should throw UnauthorizedException', async () => {
      mockReflector.get.mockReturnValue(['ANY_PERMISSION']);
      mockUserService.getUserPermissions.mockResolvedValue([]);

      const ctx = buildContext({ userId: 'user-no-perms' });

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      await expect(guard.canActivate(ctx)).rejects.toThrow('User permissions not found.');
    });
  });

  // -------------------------------------------------------------------------
  // Case insensitivity
  // -------------------------------------------------------------------------

  describe('case-insensitive permission matching', () => {
    it('should match "admin" (lowercase decorator default) against "ADMIN" stored in DB', async () => {
      mockReflector.get.mockReturnValue(['admin']);
      mockUserService.getUserPermissions.mockResolvedValue([buildPermission('ADMIN')]);

      const ctx = buildContext({ userId: 'user-1' });
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
    });
  });
});
