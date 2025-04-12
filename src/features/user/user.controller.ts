import { Controller, Get, Req, UnauthorizedException } from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiTags, ApiUnauthorizedResponse } from '@nestjs/swagger';
import { Request } from 'express';
import { UserResponseDto } from '../../shared/dto/user.dto';
@ApiBearerAuth('Bearer token')
@ApiTags('user')
@Controller('user')
export class UserController {

    @ApiOperation({ summary: "Returns the user's info." })
    @ApiOkResponse({ description: "Returns a json with the user's data" })
    @ApiUnauthorizedResponse({ description: 'Authentication failed' })
    @Get('me')
    getCurrentUser(@Req() req: Request) : UserResponseDto {
      const user: UserResponseDto = req.user as UserResponseDto;
      if (!user) {
        throw new UnauthorizedException('User is not authenticated.');
      }
      return user;
    }
}
