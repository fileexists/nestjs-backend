import { Module } from '@nestjs/common';
import { PermissionService } from './permission.service';
import { PermissionController } from './permission.controller';
import { PermissionSeeder } from '../../../scripts/permission.seed';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Permission } from '../../database/permission.entity';
import { JwtService } from '@nestjs/jwt';
import { UserModule } from '../user/user.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Permission]),
    UserModule,
    AuthModule
  ],
  providers: [
    PermissionService, 
    PermissionSeeder,
    JwtService,
  ],
  controllers: [PermissionController],
  exports: [PermissionService]
})
export class PermissionModule {}
