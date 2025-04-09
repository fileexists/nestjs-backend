import { Injectable, OnModuleInit } from '@nestjs/common';
import { PermissionService } from '../src/features/permission/permission.service';
import { PermissionDTO } from '../src/shared/dto/permission.dto';

@Injectable()
export class PermissionSeeder{
  constructor(
    private readonly permissionService: PermissionService,
  ) {}

  public async seedPermissions() {
    const defaultPermissions: PermissionDTO[] = [
      { name: 'ADMIN', description: 'Full access' },
      { name: 'USER', description: 'Basic user access' },
      { name: 'MODERATOR', description: 'Can manage content' },
    ];

    for (const permissionData of defaultPermissions) {
      const exists = await this.permissionService.findPermission({ name: permissionData.name });
      if (!exists) {
        await this.permissionService.create(permissionData);
        console.log(`✅ Created permission: ${permissionData.name}`);
      } else {
        console.log(`⚠️ Permission already exists: ${permissionData.name}`);
      }
    }
  }
}
