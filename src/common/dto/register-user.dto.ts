import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class UserAuthDTO {
  @ApiProperty({
    example: 'user@example.com',
    description: 'Email address of the user',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: 'StrongPassword123!',
    description: 'Account password',
    required: false,
  })
  @IsString()
  @IsOptional()
  @MinLength(8)
  @MaxLength(72)
  password?: string;
}

// Not implemented as `extends UserAuthDTO` on purpose: class-validator merges
// decorator metadata from parent classes, so overriding `password` in a
// subclass would NOT drop the inherited `@IsOptional()` from UserAuthDTO —
// the field would still validate as optional. A standalone DTO avoids that
// pitfall and keeps password required only where registration needs it.
export class RegisterUserDTO {
  @ApiProperty({
    example: 'user@example.com',
    description: 'Email address of the user',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: 'StrongPassword123!',
    description: 'Account password',
  })
  @IsString()
  @MinLength(8)
  @MaxLength(72)
  password: string;
}
