import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsOptional } from 'class-validator';

export class PermissionDTO {
  @ApiProperty({ example: 'ADMIN', description: 'The name of the permission' })
  @IsString()
  name: string;

  @ApiProperty({ example: 'Grants all permissions', description: 'The description of the permission', required: false })
  @IsString()
  @IsOptional()
  description?: string;
}

export class UpdatePermissionDTO {
  @ApiProperty({ example: 'ADMIN', description: 'The name of the permission', required: false })
  @IsString()
  @IsOptional()
  name?: string;

  @ApiProperty({ example: 'Grants all permissions', description: 'The description of the permission', required: false })
  @IsString()
  @IsOptional()
  description?: string;
}