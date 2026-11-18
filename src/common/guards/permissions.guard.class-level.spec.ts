/**
 * @Permissions on a controller class (real Reflector, real decorators).
 * Before: the guard only read the method, so a class-level decorator was silently ignored and
 * every route of that controller was open to any authenticated user.
 */
import {
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Permissions } from '../decorators/permissions.decorator';
import { Permission } from '../entities/permission.entity';
import { PermissionsGuard } from './permissions.guard';

@Permissions('STAFF')
class ProtectedController {
  inherited(): void {}

  @Permissions('BILLING')
  overridden(): void {}
}

class OpenController {
  anything(): void {}

  @Permissions('BILLING')
  guarded(): void {}
}

const permission = (name: string): Permission =>
  Object.assign(new Permission(), { id: name, name });

describe('PermissionsGuard - @Permissions on the class', () => {
  const getUserPermissions = jest.fn();
  const guard = new PermissionsGuard(new Reflector(), {
    getUserPermissions,
  } as never);

  const context = (
    controller: new () => object,
    method: string,
  ): ExecutionContext => {
    const handler = (controller.prototype as Record<string, () => void>)[
      method
    ];
    return {
      getHandler: () => handler,
      getClass: () => controller,
      switchToHttp: () => ({ getRequest: () => ({ user: { id: 'u1' } }) }),
    } as unknown as ExecutionContext;
  };
  const userHolds = (...names: string[]) =>
    getUserPermissions.mockResolvedValue(names.map(permission));

  beforeEach(() => jest.clearAllMocks());

  it('a method without its own decorator inherits the class one: a user without it is refused', async () => {
    userHolds('USER');

    await expect(
      guard.canActivate(context(ProtectedController, 'inherited')),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('...and a user who holds it gets in', async () => {
    userHolds('STAFF');

    await expect(
      guard.canActivate(context(ProtectedController, 'inherited')),
    ).resolves.toBe(true);
  });

  it('the method decorator replaces the class one (it does not add to it)', async () => {
    userHolds('STAFF');
    await expect(
      guard.canActivate(context(ProtectedController, 'overridden')),
    ).rejects.toBeInstanceOf(ForbiddenException);

    userHolds('BILLING');
    await expect(
      guard.canActivate(context(ProtectedController, 'overridden')),
    ).resolves.toBe(true);
  });

  it('with no decorator anywhere the route stays open to any authenticated user', async () => {
    userHolds('USER');

    await expect(
      guard.canActivate(context(OpenController, 'anything')),
    ).resolves.toBe(true);
    expect(getUserPermissions).not.toHaveBeenCalled();
  });

  it('a method decorator on a class without one still works', async () => {
    userHolds('USER');

    await expect(
      guard.canActivate(context(OpenController, 'guarded')),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('a class-level decorator also stops an anonymous request (401, not an open door)', async () => {
    const anonymous = {
      ...context(ProtectedController, 'inherited'),
      switchToHttp: () => ({ getRequest: () => ({}) }),
    } as unknown as ExecutionContext;

    await expect(guard.canActivate(anonymous)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
  });
});
