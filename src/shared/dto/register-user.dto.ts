import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsOptional, IsString, MinLength } from 'class-validator';

export class UserAuthDTO {
  @ApiProperty({ example: 'user@example.com', description: 'The email address of the user' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'strongPassword123', description: 'The password for the user account' })
  @IsString()
  @IsOptional()
  @MinLength(1)
  password?: string;
}
