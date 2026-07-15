import { Controller, Get, Req, UnauthorizedException } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { Request } from 'express';
import { UserService } from './user.service';
import { UserResponseDto } from '../../common/dto/user.dto';

@ApiBearerAuth('Bearer token')
@ApiTags('user')
@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @ApiOperation({ summary: "Returns the authenticated user's info" })
  @ApiOkResponse({
    description: "Returns the user's data",
    type: UserResponseDto,
  })
  @ApiUnauthorizedResponse({ description: 'Authentication failed' })
  @Get('me')
  async getCurrentUser(@Req() req: Request): Promise<UserResponseDto> {
    const userId = (req.user as { id?: string } | undefined)?.id;
    if (!userId) {
      throw new UnauthorizedException('User is not authenticated.');
    }

    const user = await this.userService.getUserById(userId);
    if (!user) {
      throw new UnauthorizedException('User is not authenticated.');
    }
    return user;
  }
}
