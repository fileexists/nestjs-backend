import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { UserService } from '../../modules/user/user.service';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';

/** Escapes every regex metacharacter, so the text is matched literally. */
function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly usersService: UserService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Method first, then class: `@Permissions()` on a controller protects all its routes, and one
    // on a method replaces (does not add to) the class-level one. Reading only the handler would
    // leave a class-level decorator silently ignored, i.e. the whole controller open.
    const requiredPermissions = this.reflector.getAllAndOverride<
      (string | string[])[] | undefined
    >(PERMISSIONS_KEY, [context.getHandler(), context.getClass()]);

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
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

  /**
   * Wildcard semantics: `*` is only special in the REQUIRED permission (the one written in
   * `@Permissions()`), where it stands for any run of characters, including none
   * (`MANAGE_*` matches `MANAGE_USERS` and `MANAGE_`). Matching is case-insensitive and anchored:
   * the whole name must match. Every other character is literal, so `REPORT.*` does not match
   * `REPORTX1`. A permission a user HOLDS is never a pattern: a user with `MANAGE_*` has exactly
   * that literal permission.
   */
  private matchPermission(
    required: string,
    userPermissions: Set<string>,
  ): boolean {
    if (userPermissions.has(required)) {
      return true;
    }
    if (!required.includes('*')) {
      return false;
    }
    const pattern = required.split('*').map(escapeRegExp).join('.*');
    const regex = new RegExp(`^${pattern}$`);
    return [...userPermissions].some((p) => regex.test(p));
  }
}
