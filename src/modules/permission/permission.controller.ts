import {
  Body,
  ConflictException,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  InternalServerErrorException,
  Param,
  ParseUUIDPipe,
  Post,
  Put,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiInternalServerErrorResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiTags,
} from '@nestjs/swagger';
import {
  PermissionDTO,
  UpdatePermissionDTO,
} from '../../common/dto/permission.dto';
import { PermissionService } from './permission.service';
import { Permissions } from '../../common/decorators/permissions.decorator';
import { Permission } from '../../common/entities/permission.entity';

@ApiBearerAuth('Bearer token')
@ApiTags('permission')
@Controller('permission')
export class PermissionController {
  constructor(private readonly permissionService: PermissionService) {}

  @Get()
  @ApiOperation({ summary: 'Get all permissions' })
  @ApiOkResponse({ description: 'List of permissions', type: [PermissionDTO] })
  @Permissions('admin')
  findAll(): Promise<Permission[]> {
    return this.permissionService.findAll();
  }

  @Post()
  @ApiOperation({ summary: 'Create a new permission' })
  @ApiCreatedResponse({
    description: 'Permission created',
    type: PermissionDTO,
  })
  @ApiConflictResponse({ description: 'Permission already exists' })
  @Permissions('admin')
  async create(
    @Body() dto: PermissionDTO,
  ): Promise<{ message: string; permission: Permission }> {
    try {
      dto.name = dto.name.toUpperCase();
      const permission = await this.permissionService.create(dto);
      return { message: `Permission '${permission.name}' created`, permission };
    } catch (error) {
      // PostgreSQL unique-constraint violation code
      if (error.code === '23505') {
        throw new ConflictException(`Permission '${dto.name}' already exists`);
      }
      throw new InternalServerErrorException('Error creating permission');
    }
  }

  @Put(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Update an existing permission' })
  @ApiOkResponse({
    description: 'Permission updated',
    type: UpdatePermissionDTO,
  })
  @ApiNotFoundResponse({ description: 'Permission not found' })
  @ApiInternalServerErrorResponse({ description: 'Internal Server Error' })
  @ApiParam({
    name: 'id',
    type: 'string',
    format: 'uuid',
    description: 'Permission ID',
  })
  @Permissions('admin')
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdatePermissionDTO,
  ): Promise<Permission> {
    if (dto.name) dto.name = dto.name.toUpperCase();
    return this.permissionService.update(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Delete a permission' })
  @ApiOkResponse({ description: 'Permission deleted' })
  @ApiNotFoundResponse({ description: 'Permission not found' })
  @ApiParam({
    name: 'id',
    type: 'string',
    format: 'uuid',
    description: 'Permission ID',
  })
  @Permissions('admin')
  async remove(
    @Param('id', ParseUUIDPipe) id: string,
  ): Promise<{ message: string }> {
    await this.permissionService.remove(id);
    return { message: 'Permission deleted' };
  }
}
