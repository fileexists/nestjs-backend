import { SetMetadata } from '@nestjs/common';

export const PERMISSIONS_KEY = 'permissions';

export const Permissions = (...permissions: (string | string[])[]) => {
  const defaultPermission = ['admin'];
  const resolvedPermissions = permissions.length
    ? permissions
    : [defaultPermission];
  return SetMetadata(PERMISSIONS_KEY, resolvedPermissions);
};
