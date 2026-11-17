import { Injectable, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { UserService } from '../../src/modules/user/user.service';
import { PermissionService } from '../../src/modules/permission/permission.service';
import { Permission } from '../../src/common/entities/permission.entity';

@Injectable()
export class UserSeeder {
  constructor(
    private readonly userService: UserService,
    private readonly permissionService: PermissionService,
    private readonly configService: ConfigService,
  ) {}

  async seedUser(argv: { email: string; password: string; permission: string }): Promise<void> {
    const { email, password, permission } = argv;
    const permissionNames = permission.split(',').map((n) => n.trim().toUpperCase());

    const permissionEntities = await Promise.all(
      permissionNames.map((name) => this.permissionService.findPermission({ name })),
    );

    if (permissionEntities.some((p) => !p)) {
      console.error(`One or more permissions not found: ${permissionNames.join(', ')}`);
      const available = await this.permissionService.findAll();
      console.info(`Available: ${available.map((p) => p.name).join(', ')}`);
      return;
    }

    const existingUser = await this.userService.getUserByEmail(email);
    if (existingUser) {
      throw new BadRequestException('User already registered');
    }

    const hashedPassword = await bcrypt.hash(
      password,
      Number(this.configService.get<number>('BCRYPT_ROUNDS') ?? 12),
    );
    const validPermissions = permissionEntities.filter((p): p is Permission => p !== null);

    const newUser = await this.userService.createUser({
      email,
      password: hashedPassword,
      permissions: validPermissions,
      provider: 'local',
      // Creato da un operatore (non auto-registrato): l'email e' considerata verificata.
      emailVerifiedAt: new Date(),
    });

    console.log(`User created: ${email} (ID: ${newUser.id})`);
  }

  async seedGoogleUser(argv: { email: string; permission: string }): Promise<void> {
    const { email, permission } = argv;
    const permissionNames = permission.split(',').map((n) => n.trim().toUpperCase());

    const permissionEntities = await Promise.all(
      permissionNames.map((name) => this.permissionService.findPermission({ name })),
    );

    if (permissionEntities.some((p) => !p)) {
      console.error(`One or more permissions not found: ${permissionNames.join(', ')}`);
      const available = await this.permissionService.findAll();
      console.info(`Available: ${available.map((p) => p.name).join(', ')}`);
      return;
    }

    const existingUser = await this.userService.getUserByEmail(email);
    if (existingUser) {
      throw new BadRequestException('User already registered');
    }

    const validPermissions = permissionEntities.filter((p): p is Permission => p !== null);

    const newUser = await this.userService.createUser({
      email,
      permissions: validPermissions,
      provider: 'google',
      emailVerifiedAt: new Date(),
    });

    console.log(`Google user created: ${email} (ID: ${newUser.id})`);
  }
}
