import {
  Injectable,
  NotFoundException,
  OnApplicationBootstrap,
  ServiceUnavailableException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Permission } from '../../common/entities/permission.entity';
import { isUniqueViolation } from '../../common/utils/db-errors';
import {
  PermissionDTO,
  UpdatePermissionDTO,
} from '../../common/dto/permission.dto';

/** Permissions without which the application does not work: guaranteed at every startup. */
const REQUIRED_PERMISSIONS = [
  { name: 'USER', description: 'Basic user access' },
];

@Injectable()
export class PermissionService implements OnApplicationBootstrap {
  constructor(
    @InjectRepository(Permission)
    private readonly permissionRepository: Repository<Permission>,
  ) {}

  /** Idempotent seed at startup: if an indispensable permission is missing it creates it. */
  async onApplicationBootstrap(): Promise<void> {
    await this.ensureDefaults();
  }

  /**
   * Creates the indispensable permissions if they are missing. Idempotent and safe with several instances
   * starting together (the uniqueness violation of whoever arrives second is ignored).
   * It does not touch permissions that already exist: an edited description stays as it is.
   */
  async ensureDefaults(): Promise<void> {
    for (const definition of REQUIRED_PERMISSIONS) {
      const existing = await this.permissionRepository.findOne({
        where: { name: definition.name },
      });
      if (existing) continue;
      try {
        await this.permissionRepository.save(
          this.permissionRepository.create(definition),
        );
      } catch (error) {
        if (!isUniqueViolation(error)) throw error;
      }
    }
  }

  /**
   * Indispensable permission (e.g. USER): if it is missing the user is NOT silently created
   * without permissions, the answer is 503.
   */
  async getRequired(name: string): Promise<Permission> {
    const permission = await this.permissionRepository.findOne({
      where: { name },
    });
    if (!permission) {
      throw new ServiceUnavailableException(
        `Required permission "${name}" is missing: the service is not ready.`,
      );
    }
    return permission;
  }

  async findPermission(
    filter: Partial<Permission>,
  ): Promise<Permission | null> {
    return this.permissionRepository.findOne({ where: filter });
  }

  async findAll(): Promise<Permission[]> {
    return this.permissionRepository.find();
  }

  async create(createPermissionDto: PermissionDTO): Promise<Permission> {
    const permission = this.permissionRepository.create(createPermissionDto);
    return this.permissionRepository.save(permission);
  }

  async update(
    id: string,
    updatePermissionDto: UpdatePermissionDTO,
  ): Promise<Permission> {
    const permission = await this.permissionRepository.findOne({
      where: { id },
    });

    if (!permission) {
      throw new NotFoundException('Permission not found');
    }

    Object.assign(permission, updatePermissionDto);
    return this.permissionRepository.save(permission);
  }

  async remove(id: string): Promise<void> {
    const permission = await this.permissionRepository.findOne({
      where: { id },
    });
    if (!permission) {
      throw new NotFoundException('Permission not found');
    }
    await this.permissionRepository.delete(id);
  }
}
