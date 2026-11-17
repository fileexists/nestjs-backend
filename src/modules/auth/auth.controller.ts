import {
  Controller,
  Post,
  Body,
  Get,
  UnauthorizedException,
  Res,
  UseFilters,
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
  ApiResponse,
  ApiTags,
  ApiTooManyRequestsResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { Throttle } from '@nestjs/throttler';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { AccountService } from './account.service';
import { GoogleCallbackExceptionFilter } from './google-callback.filter';
import { buildFrontendRedirect, frontendOrigins } from './frontend-redirect';
import { GoogleProfilePayload } from '../../common/interfaces/jwt-payload.interface';
import {
  ResendVerificationDTO,
  VerifyEmailDTO,
} from '../../common/dto/account.dto';
import {
  UserAuthDTO,
  RegisterUserDTO,
} from '../../common/dto/register-user.dto';
import { Public } from '../../common/decorators/public.decorator';
import {
  GoogleCallbackGuard,
  GoogleOAuthGuard,
} from '../../common/guards/google-oauth.guard';

@ApiTags('auth')
@Controller('auth')
@Public()
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly accountService: AccountService,
    private readonly configService: ConfigService,
  ) {}

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Log out: revoke the current refresh token and clear auth cookies',
  })
  @ApiOkResponse({ description: 'User logged out successfully' })
  async logout(@Req() req: Request, @Res() res: Response): Promise<void> {
    await this.authService.logout(
      req.cookies?.refresh_token as string | undefined,
    );
    this.authService.clearAuthCookies(res);
    res.json({ message: 'User has been logged out successfully.' });
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 30, ttl: 60_000 } })
  @ApiOperation({
    summary: 'Rotate the refresh token and issue a new access token',
  })
  @ApiOkResponse({ description: 'Tokens refreshed (new cookies set)' })
  @ApiUnauthorizedResponse({ description: 'Invalid, expired or reused token' })
  async refresh(@Req() req: Request, @Res() res: Response): Promise<void> {
    const refreshToken = req.cookies?.refresh_token as string | undefined;
    if (!refreshToken) {
      throw new UnauthorizedException('User is not authenticated.');
    }
    const { token, refreshToken: rotated } =
      await this.authService.refreshTokens(refreshToken);
    this.authService.setAuthCookies(res, token, rotated);
    res.json({ message: 'Tokens refreshed.' });
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
    this.authService.clearAuthCookies(res);
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

  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  @ApiOperation({ summary: 'Confirm an email address with the emailed token' })
  @ApiOkResponse({ description: 'Email verified' })
  @ApiBadRequestResponse({
    description: 'Invalid, expired or already used token',
  })
  @ApiTooManyRequestsResponse({ description: 'Too many requests' })
  async verifyEmail(
    @Body() body: VerifyEmailDTO,
  ): Promise<{ message: string }> {
    await this.accountService.verifyEmail(body.token);
    return { message: 'Email verified successfully.' };
  }

  @Post('resend-verification')
  @HttpCode(HttpStatus.ACCEPTED)
  @Throttle({ default: { limit: 3, ttl: 60_000 } })
  @ApiOperation({ summary: 'Resend the email verification message' })
  @ApiBody({ type: ResendVerificationDTO })
  @ApiTooManyRequestsResponse({ description: 'Too many requests' })
  async resendVerification(
    @Body() body: ResendVerificationDTO,
  ): Promise<{ message: string }> {
    await this.accountService.resendVerification(body.email);
    // Stessa risposta per qualsiasi indirizzo: non rivela se l'account esiste.
    return {
      message:
        'If the address belongs to an account awaiting verification, a new email has been sent.',
    };
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
        this.authService.setAuthCookies(res, newAccessToken, newRefreshToken);

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
  @UseGuards(GoogleCallbackGuard)
  @UseFilters(GoogleCallbackExceptionFilter)
  @ApiOperation({
    summary:
      'Google OAuth callback: sets the session cookies and redirects to the frontend',
  })
  @ApiResponse({
    status: 302,
    description:
      'Redirect to FRONTEND_URL/auth/callback?status=success, or ?status=error&reason=<code>',
  })
  async googleAuthRedirect(
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const googleUser = req.user as Required<
      Pick<GoogleProfilePayload, 'email' | 'googleId'>
    >;
    await this.authService.handleGoogleCallback(googleUser, res);
    res.redirect(
      HttpStatus.FOUND,
      buildFrontendRedirect(
        frontendOrigins(this.configService),
        req.oauthRedirectIndex ?? 0,
        { status: 'success' },
      ),
    );
  }
}
