import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Permission } from '../../database/permission.entity';
import { PermissionDTO, UpdatePermissionDTO } from '../../shared/dto/permission.dto';
import { Repository } from 'typeorm';

@Injectable()
export class PermissionService {
    constructor(
        @InjectRepository(Permission)
        private readonly permissionRepository: Repository<Permission>,
    ){}

    async findPermission(filter: Partial<Permission>): Promise<Permission | null> {
        return this.permissionRepository.findOne({
          where: filter,
          relations: ['users'],
        });
    }

    async findAll(): Promise<Permission[]> {
        return await this.permissionRepository.find();
    }

    async create(createPermissionDto: PermissionDTO): Promise<Permission> {
        const permission = this.permissionRepository.create(createPermissionDto);
        return await this.permissionRepository.save(permission);
    }

    async update(id: string, updatePermissionDto: UpdatePermissionDTO): Promise<Permission> {
        const permission = await this.permissionRepository.findOne({ where: { id } });
    
        if (!permission) {
          throw new NotFoundException('Permission not found');
        }
    
        Object.assign(permission, updatePermissionDto);
    
        return await this.permissionRepository.save(permission);
    }  

    async remove(id: string): Promise<void> {
        await this.permissionRepository.delete(id);
    }
}
