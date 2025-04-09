import * as dotenv from 'dotenv';
dotenv.config({path: '../.env'});
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserService } from './features/user/user.service';
import { AuthModule } from './features/auth/auth.module';
import { User } from './database/user.entity';
import { APP_GUARD } from '@nestjs/core';
import { Permission } from './database/permission.entity';
import { PermissionsGuard } from './shared/guards/permissions.guard';
import { UserModule } from './features/user/user.module';
import { PermissionService } from './features/permission/permission.service';
import { PermissionModule } from './features/permission/permission.module';
import { AuthGuard } from './shared/guards/auth.guard';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'mysql',
      url: process.env.DATABASE_URL,
      entities: [User, Permission],
      synchronize: process.env.NODE_ENV === "development",
      logging: process.env.NODE_ENV === "development",
    }),
    AuthModule,
    UserModule,
    PermissionModule,
    ThrottlerModule.forRoot({
      throttlers: [
        {
          ttl: 60000,
          limit: 3,
        },
      ],
    }),
  ],
  providers: [
    UserService,
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: PermissionsGuard,
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    },
    PermissionService,
  ],
})
export class AppModule  { }
