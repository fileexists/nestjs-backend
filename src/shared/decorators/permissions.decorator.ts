import { SetMetadata } from '@nestjs/common';

export const Permissions = (...permissions: (string | string[])[]) => {
  const defaultPermission = ['admin'];

  const resolvedPermissions = permissions.length ? permissions : [defaultPermission];

  return SetMetadata('permissions', resolvedPermissions);
};
