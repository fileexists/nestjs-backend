import { Controller, Post, Body, Get, BadRequestException, UnauthorizedException, Res, UseGuards, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiBadRequestResponse, ApiBody, ApiCreatedResponse, ApiOkResponse, ApiOperation, ApiTags, ApiUnauthorizedResponse } from '@nestjs/swagger';
import { UserAuthDTO } from '../../shared/dto/register-user.dto';
import { UserService } from '../user/user.service';
import { Response } from 'express';
import { PermissionService } from '../permission/permission.service';
import { Public } from '../../shared/decorators/public.decorator';
import { GoogleOAuthGuard } from '../../shared/guards/google-oauth.guard';

@ApiTags('auth')
@Controller('auth')
@Public()
export class AuthController {
  constructor(
    private authService: AuthService,
    private userService: UserService,
    private permissionService: PermissionService,
  ) {}

  @ApiOperation({ summary: 'Logs out a user' })
  @ApiOkResponse({ description: 'User has been logged out successfully.' })
  @Get('logout')
  async logout(@Res() response: Response) {
    response.clearCookie('access_token');
    response.clearCookie('refresh_token');

    return response.json({ message: 'User has been logged out successfully.' });

  }

  @ApiOperation({ summary: 'Registers a new user' })
  @ApiCreatedResponse({ description: 'The user has been successfully created.' })
  @ApiBadRequestResponse({ description: 'User already registered' })
  @ApiBody({ type: UserAuthDTO })
  @Post('register')
  async register(@Body() body: UserAuthDTO){
    const existingUser = await this.userService.getUserByEmail(body.email);
    if (existingUser) {
      throw new BadRequestException('User already registered');
    }
  
    const hashedPassword = await this.authService.hashPassword(body.password);
    const userRole = await this.permissionService.findPermission({ name: 'USER' });
    const newUser = await this.userService.createUser({ 
      email: body.email, 
      password: hashedPassword,
      permissions: userRole ? [userRole] : [],
      provider: 'local',
    });
  
    return { message: 'User registered successfully', userId: newUser.id };
  }

  @ApiOperation({ summary: 'Log in for an existing user' })
  @ApiCreatedResponse({ description: 'Login was successful.' })
  @ApiBadRequestResponse({ description: 'User does not exist' })
  @ApiUnauthorizedResponse({ description: 'Invalid credentials or different login method' })
  @ApiBody({ type: UserAuthDTO })
  @Post('login')
  async login(@Body() body: UserAuthDTO, @Res() response: Response) {
    const existingUser = await this.userService.getUserByEmail(body.email);
    if (!existingUser) {
      throw new UnauthorizedException('Invalid email or password');
    }
  
    if (existingUser.provider && (existingUser.provider !== 'local' && existingUser.provider !== 'combined')) {
      throw new UnauthorizedException(
        'Please login via google.'
      );
    }
  
    if (!body.password || !existingUser.password) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isPasswordValid = await this.authService.comparePasswords(body.password, existingUser.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }
  
    const token = await this.authService.generateJwtToken(existingUser);
    const refreshToken = await this.authService.generateRefreshToken(existingUser);

    const { accessTokenOptions, refreshTokenOptions } = this.authService.getCookieOptions();
  
    response.cookie('access_token', token, accessTokenOptions);
    response.cookie('refresh_token', refreshToken, refreshTokenOptions);
  
    return response.json({ message: 'Login successful.' });
  }

  @ApiOperation({ summary: 'Redirects to Google authentication' })
  @ApiOkResponse({ description: 'Successfully authenticated with Google.' })
  @Get('google')
  @UseGuards(GoogleOAuthGuard)
  async googleAuth() { }

  @ApiOperation({ summary: 'Handles Google authentication callback' })
  @ApiOkResponse({ description: 'Google authentication was successful.' })
  @ApiUnauthorizedResponse({ description: 'Authentication failed' })
  @Get('google/callback')
  @UseGuards(GoogleOAuthGuard)
  async googleAuthRedirect(@Req() req, @Res() response: Response) {

    let user = await this.userService.getUserByEmail(req.user.email);
    if (!user) {
      const userRole = await this.permissionService.findPermission({ name: 'USER' });

      user = await this.userService.createUser({ 
        email: req.user.email, 
        provider: 'google',
        googleId: req.user.googleId,
        permissions: userRole ? [userRole] : [],
      });
    }
    else {
      if(user.password){
        user = await this.userService.updateUser(user.id, {
          provider: 'combined',
          googleId: req.user.googleId,
       });
      }
    }
  
    const token = await this.authService.generateJwtToken(user);
    const refreshToken = await this.authService.generateRefreshToken(user);

    const { accessTokenOptions, refreshTokenOptions } = this.authService.getCookieOptions();
  
    response.cookie('access_token', token, accessTokenOptions);
    response.cookie('refresh_token', refreshToken, refreshTokenOptions);
  
    return response.json({ message: 'Authentication with google was successful.' });
  }
}
