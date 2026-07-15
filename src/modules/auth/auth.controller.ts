import {
  Controller,
  Post,
  Body,
  Get,
  UnauthorizedException,
  Res,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiBody,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiTooManyRequestsResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import {
  UserAuthDTO,
  RegisterUserDTO,
} from '../../common/dto/register-user.dto';
import { Public } from '../../common/decorators/public.decorator';
import { GoogleOAuthGuard } from '../../common/guards/google-oauth.guard';

@ApiTags('auth')
@Controller('auth')
@Public()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Log out a user and clear auth cookies' })
  @ApiOkResponse({ description: 'User logged out successfully' })
  logout(@Res() res: Response): void {
    res.clearCookie('access_token', { path: '/' });
    res.clearCookie('refresh_token', { path: '/' });
    res.json({ message: 'User has been logged out successfully.' });
  }

  @Post('logout-all')
  @Public(false)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Revoke all active sessions for the current user' })
  @ApiOkResponse({ description: 'All sessions revoked' })
  @ApiUnauthorizedResponse({ description: 'User is not authenticated' })
  async logoutAll(@Req() req: Request, @Res() res: Response): Promise<void> {
    const user = req.user as { id: string };
    await this.authService.revokeSessions(user.id);
    res.clearCookie('access_token', { path: '/' });
    res.clearCookie('refresh_token', { path: '/' });
    res.json({ message: 'All sessions have been revoked.' });
  }

  @Post('register')
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @ApiOperation({ summary: 'Register a new user with email and password' })
  @ApiCreatedResponse({ description: 'User created successfully' })
  @ApiBadRequestResponse({ description: 'Email already registered' })
  @ApiTooManyRequestsResponse({ description: 'Too many requests' })
  @ApiBody({ type: RegisterUserDTO })
  register(
    @Body() body: RegisterUserDTO,
  ): Promise<{ message: string; userId: string }> {
    return this.authService.register(body);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @ApiOperation({ summary: 'Log in with email and password' })
  @ApiOkResponse({ description: 'Login successful' })
  @ApiUnauthorizedResponse({ description: 'Invalid credentials' })
  @ApiTooManyRequestsResponse({ description: 'Too many requests' })
  @ApiBody({ type: UserAuthDTO })
  login(@Body() body: UserAuthDTO, @Res() res: Response): Promise<void> {
    return this.authService.login(body, res);
  }

  @Get('validate')
  @ApiOperation({
    summary: "Validate the user's access token (auto-refreshes if expired)",
  })
  @ApiOkResponse({ description: 'Token is valid' })
  @ApiUnauthorizedResponse({ description: 'User is not authenticated' })
  async validateToken(
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const accessToken = req.cookies?.access_token as string | undefined;

    try {
      await this.authService.verifyJwtToken(accessToken);
      res.json({ success: true });
      return;
    } catch {
      const refreshToken = req.cookies?.refresh_token as string | undefined;

      if (!accessToken && !refreshToken) {
        throw new UnauthorizedException('User is not authenticated.');
      }

      try {
        const { token: newAccessToken, refreshToken: newRefreshToken } =
          await this.authService.refreshTokens(refreshToken!);
        const { accessTokenOptions, refreshTokenOptions } =
          this.authService.getCookieOptions();

        res.cookie('access_token', newAccessToken, accessTokenOptions);
        res.cookie('refresh_token', newRefreshToken, refreshTokenOptions);

        await this.authService.verifyJwtToken(newAccessToken);
        res.json({ success: true });
      } catch {
        throw new UnauthorizedException('User is not authenticated.');
      }
    }
  }

  @Get('google')
  @UseGuards(GoogleOAuthGuard)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  @ApiOperation({ summary: 'Redirect to Google OAuth consent screen' })
  @ApiOkResponse({ description: 'Redirects to Google' })
  @ApiTooManyRequestsResponse({ description: 'Too many requests' })
  googleAuth(): void {}

  @Get('google/callback')
  @UseGuards(GoogleOAuthGuard)
  @ApiOperation({ summary: 'Google OAuth callback handler' })
  @ApiOkResponse({ description: 'Google authentication successful' })
  @ApiUnauthorizedResponse({ description: 'Authentication failed' })
  googleAuthRedirect(@Req() req: Request, @Res() res: Response): Promise<void> {
    const googleUser = req.user as { email: string; googleId: string };
    return this.authService.handleGoogleCallback(googleUser, res);
  }
}
