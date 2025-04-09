import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, ForbiddenException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { UserService } from "../../features/user/user.service";
import { PermissionDTO } from "../dto/permission.dto";

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private usersService: UserService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.get<(string | string[])[]>('permissions', context.getHandler());
    if (!requiredPermissions) {
      return true;
    }
  
    const request = context.switchToHttp().getRequest();
    const userId = request.user?.id;

    if (!userId) {
      throw new UnauthorizedException('User is not authenticated.');
    }

    //const userPermissions = await this.usersService.getUserPermissions(userId); Use this if you want to fetch them from the database
    const userPermissions: PermissionDTO[] = request.user?.permissions; 

    if (!userPermissions) {
      throw new UnauthorizedException('User permissions not found');
    }

    const userPermissionSet = new Set(userPermissions.map(permission => permission.name.toUpperCase()));

    const hasPermission = (permissions: (string | string[])[]) => {
      return permissions.every(permission =>
        Array.isArray(permission)
          ? permission.some(p => this.matchesPermission(p, userPermissionSet))
          : this.matchesPermission(permission, userPermissionSet)
      );
    };

    const permissionCheck = hasPermission(requiredPermissions);

    if (!permissionCheck) {
      throw new ForbiddenException('You do not have permission to access this resource');
    }

    return true;
  }

  private matchesPermission(permission: string, userPermissions: Set<string>): boolean {
    const normalizedPermission = permission.toUpperCase();

    if (normalizedPermission.includes('*')) {
      const regex = new RegExp(`^${normalizedPermission.replace(/\*/g, '.*')}$`);
      return Array.from(userPermissions).some(userPermission => regex.test(userPermission));
    }

    return Array.from(userPermissions).some(userPermission => 
      userPermission.localeCompare(normalizedPermission, undefined, { sensitivity: 'base' }) === 0
    );
  }
}
