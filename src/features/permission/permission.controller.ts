import { Body, ConflictException, Controller, Delete, Get, InternalServerErrorException, Param, Post, Put, Res, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiConflictResponse, ApiCreatedResponse, ApiInternalServerErrorResponse, ApiNoContentResponse, ApiNotFoundResponse, ApiOkResponse, ApiOperation, ApiParam, ApiTags } from '@nestjs/swagger';
import { PermissionDTO, UpdatePermissionDTO } from '../../shared/dto/permission.dto';
import { PermissionService } from './permission.service';
import { Response } from 'express';
import { Permissions } from '../../shared/decorators/permissions.decorator';
@ApiBearerAuth('Bearer token')
@ApiTags('permission')
@Controller('permission')
// @Permissions('admin') Use here or on each endpoint
export class PermissionController {
    constructor(private readonly permissionService: PermissionService) {}

    @Get()
    @ApiOperation({ summary: 'Get all permissions' })
    @ApiOkResponse({ description: 'List of permissions', type: PermissionDTO })
    @Permissions('admin')
    async findAll() {
      return this.permissionService.findAll();
    }
  
    @Post()
    @ApiOperation({ summary: 'Create a new permission' })
    @ApiCreatedResponse({ description: 'The permission has been created', type: PermissionDTO })
    @ApiConflictResponse({ description: 'The permission already exists' })
    @Permissions('admin')
    async create(@Body() createPermissionDto: PermissionDTO) {
      try {
        createPermissionDto.name = createPermissionDto.name.toUpperCase();
        const permission = await this.permissionService.create(createPermissionDto);
        return { message: `Permission '${permission.name}' created`, permission };
      } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
          throw new ConflictException(`Error: Permission '${createPermissionDto.name}' already exists!`);
        }
        throw new InternalServerErrorException('Error creating permission');
      }
    }
  
    @Put(':id')
    @ApiOperation({ summary: 'Update an existing permission' })
    @ApiOkResponse({ description: 'The permission has been updated', type: UpdatePermissionDTO })
    @ApiNotFoundResponse({ description: 'Permission not found' })
    @ApiInternalServerErrorResponse({ description: 'Internal Server Error' })
    @ApiParam({ name: 'id', type: 'string', description: 'Permission ID to update' })
    @Permissions('admin')
    async update(
      @Param('id') id: string,
      @Body() updatePermissionDto: UpdatePermissionDTO,
      @Res() res: Response
    ) {
      try {
        const updatedPermission = await this.permissionService.update(id, updatePermissionDto);
        return res.status(200).json(updatedPermission);
      } catch (error) {
        if (error.status === 404) {
          return res.status(error.status).json({ message: error.message });
        }
    
        return res.status(500).json({ message: 'Internal Server Error' });
      }
    }
  
    @Delete(':id')
    @ApiOperation({ summary: 'Delete a permission' })
    @ApiNoContentResponse({ description: 'The permission has been deleted' })
    @ApiParam({ name: 'id', type: 'string', description: 'Permission ID to delete' })
    @Permissions('admin')
    async remove(@Param('id') id: string, @Res() res: Response) {
      this.permissionService.remove(id);
      return res.status(201).json({ message: 'Permission deleted' });

    }
}
