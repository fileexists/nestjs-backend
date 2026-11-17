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

/** Permessi senza i quali l'applicazione non funziona: vengono garantiti a ogni avvio. */
const REQUIRED_PERMISSIONS = [
  { name: 'USER', description: 'Basic user access' },
];

@Injectable()
export class PermissionService implements OnApplicationBootstrap {
  constructor(
    @InjectRepository(Permission)
    private readonly permissionRepository: Repository<Permission>,
  ) {}

  /** Seed idempotente all'avvio: se un permesso indispensabile manca lo crea. */
  async onApplicationBootstrap(): Promise<void> {
    await this.ensureDefaults();
  }

  /**
   * Crea i permessi indispensabili se mancano. Idempotente e sicuro con piu' istanze
   * che partono insieme (la violazione di unicita' di chi arriva secondo e' ignorata).
   * Non tocca i permessi gia' presenti: una descrizione modificata resta com'e'.
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
   * Permesso indispensabile (es. USER): se manca NON si crea l'utente senza permessi
   * in silenzio, si risponde 503.
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
    return this.permissionRepository.findOne({
      where: filter,
      relations: { users: true },
    });
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
