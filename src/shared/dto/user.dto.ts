import { IsEmail, IsOptional, IsString, IsUUID, Length } from 'class-validator';
import { Permission } from '../../database/permission.entity';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsOptional()
  @IsString()
  @Length(8, 255)
  password?: string;

  @IsOptional()
  @IsString()
  @Length(1, 255)
  googleId?: string;

  @IsOptional()
  @IsString()
  @Length(1, 50)
  provider?: string;

  permissions: Permission[];
}

export class UpdateUserDto {
  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsString()
  @Length(8, 255)
  password?: string;

  @IsOptional()
  @IsString()
  googleId?: string;

  @IsOptional()
  @IsString()
  @Length(1, 50)
  provider?: string;

  @IsOptional()
  permissions?: Permission[];
}

export class UserResponseDto {
  @IsUUID()
  id: string;

  @IsEmail()
  email: string;

  @IsOptional()
  @IsString()
  googleId?: string;

  @IsOptional()
  @IsString()
  provider?: string;

  @IsOptional()
  permissions: Permission[];

  createdAt: Date;
  updatedAt: Date;
}
