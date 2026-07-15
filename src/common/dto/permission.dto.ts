import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsOptional } from 'class-validator';

export class PermissionDTO {
  @ApiProperty({ example: 'ADMIN', description: 'Name of the permission' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({
    example: 'Grants full access',
    description: 'Description of the permission',
  })
  @IsString()
  @IsNotEmpty()
  description: string;
}

export class UpdatePermissionDTO {
  @ApiProperty({
    example: 'ADMIN',
    description: 'Name of the permission',
    required: false,
  })
  @IsString()
  @IsOptional()
  name?: string;

  @ApiProperty({
    example: 'Grants full access',
    description: 'Description of the permission',
    required: false,
  })
  @IsString()
  @IsOptional()
  description?: string;
}
