import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserService } from '../../features/user/user.service';
import { PermissionDTO } from '../dto/permission.dto';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private usersService: UserService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.get<(string | string[])[]>('permissions', context.getHandler());

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const userId = request.user?.id;

    if (!userId) {
      throw new UnauthorizedException('User is not authenticated.');
    }

    const userPermissions: PermissionDTO[] = await this.usersService.getUserPermissions(userId) ?? [];

    if (!userPermissions || userPermissions.length === 0) {
      throw new UnauthorizedException('User permissions not found.');
    }

    const userPermissionSet = new Set(
      userPermissions.map(p => p.name.toUpperCase())
    );

    // We take for granted that ADMIN is the highest permission
    if (userPermissionSet.has('ADMIN')) {
      return true;
    }

    const hasPermission = (permissions: (string | string[])[]): boolean => {
      return permissions.some(permissionGroup => {
        const normalizedGroup = Array.isArray(permissionGroup)
          ? permissionGroup
          : [permissionGroup];

        return normalizedGroup.every(p =>
          this.checkPermission(p.toUpperCase(), userPermissionSet)
        );
      });
    };

    if (!hasPermission(requiredPermissions)) {
      throw new ForbiddenException('You do not have permission to access this resource.');
    }

    return true;
  }

  private checkPermission(permission: string, userPermissions: Set<string>): boolean {
    if (userPermissions.has(permission)) {
      return true;
    }

    // Wildcard support (es: "manage_*")
    if (permission.includes('*')) {
      const regex = new RegExp(`^${permission.replace(/\*/g, '.*')}$`);
      return Array.from(userPermissions).some(userPerm => regex.test(userPerm));
    }

    return false;
  }
}