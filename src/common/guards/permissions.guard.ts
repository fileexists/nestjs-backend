import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserService } from '../../modules/user/user.service';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly usersService: UserService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.get<(string | string[])[]>(
      PERMISSIONS_KEY,
      context.getHandler(),
    );

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const userId = request.user?.id;

    if (!userId) {
      throw new UnauthorizedException('User is not authenticated.');
    }

    const userPermissions =
      (await this.usersService.getUserPermissions(userId)) ?? [];

    if (userPermissions.length === 0) {
      throw new ForbiddenException(
        'You do not have permission to access this resource.',
      );
    }

    const userPermissionSet = new Set(
      userPermissions.map((p) => p.name.toUpperCase()),
    );

    if (userPermissionSet.has('ADMIN')) {
      return true;
    }

    const hasPermission = (permissions: (string | string[])[]): boolean =>
      permissions.some((group) => {
        const normalized = Array.isArray(group) ? group : [group];
        return normalized.every((p) =>
          this.matchPermission(p.toUpperCase(), userPermissionSet),
        );
      });

    if (!hasPermission(requiredPermissions)) {
      throw new ForbiddenException(
        'You do not have permission to access this resource.',
      );
    }

    return true;
  }

  private matchPermission(
    required: string,
    userPermissions: Set<string>,
  ): boolean {
    if (userPermissions.has(required)) {
      return true;
    }
    if (required.includes('*')) {
      const regex = new RegExp(`^${required.replace(/\*/g, '.*')}$`);
      return [...userPermissions].some((p) => regex.test(p));
    }
    return false;
  }
}
