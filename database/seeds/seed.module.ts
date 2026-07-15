import { Module } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { UserModule } from '../../src/modules/user/user.module';
import { PermissionModule } from '../../src/modules/permission/permission.module';
import { PermissionSeeder } from './permission.seed';
import { UserSeeder } from './user.seed';

@Module({
  imports: [AppModule, UserModule, PermissionModule],
  providers: [PermissionSeeder, UserSeeder],
})
export class SeedModule {}
