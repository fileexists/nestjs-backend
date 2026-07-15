import {
  BadRequestException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { CookieOptions, Response } from 'express';
import type { StringValue } from 'ms';
import { UserService } from '../user/user.service';
import { PermissionService } from '../permission/permission.service';
import { UserAuthDTO } from '../../common/dto/register-user.dto';

interface TokenPayload {
  id?: string;
  email?: string;
  tokenVersion?: number;
  iat?: number;
  exp?: number;
}

function parseDurationMs(duration: string): number {
  const match = /^(\d+)(ms|s|m|h|d|w)$/.exec(duration);
  if (!match) return 0;
  const value = parseInt(match[1], 10);
  const units: Record<string, number> = {
    ms: 1,
    s: 1_000,
    m: 60_000,
    h: 3_600_000,
    d: 86_400_000,
    w: 604_800_000,
  };
  return value * (units[match[2]] ?? 0);
}

@Injectable()
export class AuthService {
  private readonly jwtSecret: string;
  private readonly refreshTokenSecret: string;
  private readonly jwtExpiration: string;
  private readonly refreshTokenExpiration: string;

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly permissionService: PermissionService,
  ) {
    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    const refreshSecret = this.configService.get<string>(
      'REFRESH_TOKEN_SECRET',
    );

    if (!jwtSecret)
      throw new Error('JWT_SECRET environment variable is required');
    if (!refreshSecret)
      throw new Error('REFRESH_TOKEN_SECRET environment variable is required');

    this.jwtSecret = jwtSecret;
    this.refreshTokenSecret = refreshSecret;
    this.jwtExpiration =
      this.configService.get<string>('JWT_EXPIRATION') ?? '15m';
    this.refreshTokenExpiration =
      this.configService.get<string>('REFRESH_TOKEN_EXPIRATION') ?? '7d';
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }

  async comparePasswords(
    plainPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(plainPassword, hashedPassword);
  }

  async generateJwtToken(user: TokenPayload): Promise<string> {
    return this.jwtService.signAsync(
      { id: user.id, email: user.email },
      { secret: this.jwtSecret, expiresIn: this.jwtExpiration as StringValue },
    );
  }

  async generateRefreshToken(user: TokenPayload): Promise<string> {
    return this.jwtService.signAsync(
      {
        id: user.id,
        email: user.email,
        tokenVersion: user.tokenVersion,
      },
      {
        secret: this.refreshTokenSecret,
        expiresIn: this.refreshTokenExpiration as StringValue,
      },
    );
  }

  async verifyJwtToken(token: string | undefined): Promise<unknown> {
    try {
      if (!token) throw new Error('No token provided');
      return await this.jwtService.verifyAsync(token, {
        secret: this.jwtSecret,
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async refreshTokens(
    refreshToken: string,
  ): Promise<{ token: string; refreshToken: string }> {
    try {
      const decoded = await this.jwtService.verifyAsync<TokenPayload>(
        refreshToken,
        {
          secret: this.refreshTokenSecret,
        },
      );

      if (!decoded.id) {
        throw new UnauthorizedException('Invalid or expired refresh token');
      }

      const user = await this.userService.getUserById(decoded.id);
      if (!user) {
        throw new UnauthorizedException('Invalid or expired refresh token');
      }

      if ((decoded.tokenVersion ?? 0) !== user.tokenVersion) {
        throw new UnauthorizedException('Invalid or expired refresh token');
      }

      const newAccessToken = await this.generateJwtToken(user);
      const newRefreshToken = await this.generateRefreshToken(user);
      return { token: newAccessToken, refreshToken: newRefreshToken };
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async revokeSessions(userId: string): Promise<void> {
    await this.userService.incrementTokenVersion(userId);
  }

  getCookieOptions(): {
    accessTokenOptions: CookieOptions;
    refreshTokenOptions: CookieOptions;
  } {
    const isProduction =
      this.configService.get<string>('NODE_ENV') === 'production';

    const base: CookieOptions = {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/',
    };

    return {
      accessTokenOptions: {
        ...base,
        maxAge: parseDurationMs(this.jwtExpiration),
      },
      refreshTokenOptions: {
        ...base,
        maxAge: parseDurationMs(this.refreshTokenExpiration),
      },
    };
  }

  async register(
    dto: UserAuthDTO,
  ): Promise<{ message: string; userId: string }> {
    const existing = await this.userService.getUserByEmail(dto.email);
    if (existing) throw new BadRequestException('User already registered');

    const hashedPassword = await this.hashPassword(dto.password ?? '');
    const userRole = await this.permissionService.findPermission({
      name: 'USER',
    });
    const user = await this.userService.createUser({
      email: dto.email,
      password: hashedPassword,
      permissions: userRole ? [userRole] : [],
      provider: 'local',
    });

    return { message: 'User registered successfully', userId: user.id };
  }

  async login(dto: UserAuthDTO, res: Response): Promise<void> {
    const user = await this.userService.getUserByEmail(dto.email);
    if (!user) throw new UnauthorizedException('Invalid email or password');

    if (!user.password && user.provider === 'google') {
      throw new UnauthorizedException('Please login via google.');
    }

    if (!dto.password || !user.password) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const valid = await this.comparePasswords(dto.password, user.password);
    if (!valid) throw new UnauthorizedException('Invalid email or password');

    const token = await this.generateJwtToken(user);
    const refreshToken = await this.generateRefreshToken(user);
    const { accessTokenOptions, refreshTokenOptions } = this.getCookieOptions();

    res.cookie('access_token', token, accessTokenOptions);
    res.cookie('refresh_token', refreshToken, refreshTokenOptions);

    if (user.provider === 'google') {
      await this.userService.updateUser(user.id, { provider: 'combined' });
    }

    res.status(HttpStatus.OK).json({ message: 'Login successful.' });
  }

  async handleGoogleCallback(
    googleUser: { email: string; googleId: string },
    res: Response,
  ): Promise<void> {
    let user = await this.userService.getUserByEmail(googleUser.email);

    if (!user) {
      const userRole = await this.permissionService.findPermission({
        name: 'USER',
      });
      user = await this.userService.createUser({
        email: googleUser.email,
        provider: 'google',
        googleId: googleUser.googleId,
        permissions: userRole ? [userRole] : [],
      });
    } else if (!user.googleId) {
      user = await this.userService.updateUser(user.id, {
        googleId: googleUser.googleId,
      });
    } else if (user.password) {
      user = await this.userService.updateUser(user.id, {
        provider: 'combined',
        googleId: googleUser.googleId,
      });
    }

    const token = await this.generateJwtToken(user);
    const refreshToken = await this.generateRefreshToken(user);
    const { accessTokenOptions, refreshTokenOptions } = this.getCookieOptions();

    res.cookie('access_token', token, accessTokenOptions);
    res.cookie('refresh_token', refreshToken, refreshTokenOptions);
    res.json({ message: 'Authentication with google was successful.' });
  }
}
