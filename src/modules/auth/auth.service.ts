import {
  BadRequestException,
  ForbiddenException,
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
import { AccountService } from './account.service';
import { AuthTokenService } from './auth-token.service';
import { parseDurationMs } from '../../common/utils/duration';
import { User } from '../../common/entities/user.entity';
import { UserAuthDTO } from '../../common/dto/register-user.dto';
import { TokenPayload } from '../../common/interfaces/jwt-payload.interface';

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
    private readonly authTokenService: AuthTokenService,
    private readonly accountService: AccountService,
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

  async verifyJwtToken(token: string | undefined): Promise<TokenPayload> {
    try {
      if (!token) throw new Error('No token provided');
      return await this.jwtService.verifyAsync<TokenPayload>(token, {
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

    await this.accountService.sendVerification(user);

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

    // Dopo la password corretta: chi la conosce puo' sapere che l'email non e' verificata.
    if (!user.emailVerifiedAt) {
      throw new ForbiddenException(
        'Email not verified. Check your inbox for the verification link.',
      );
    }

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
    const user = await this.resolveGoogleUser(googleUser);

    const token = await this.generateJwtToken(user);
    const refreshToken = await this.generateRefreshToken(user);
    const { accessTokenOptions, refreshTokenOptions } = this.getCookieOptions();

    res.cookie('access_token', token, accessTokenOptions);
    res.cookie('refresh_token', refreshToken, refreshTokenOptions);
    res.json({ message: 'Authentication with google was successful.' });
  }

  /**
   * Trova o crea l'utente per un profilo Google GIA' con email verificata da Google
   * (lo garantisce la strategia). Regole contro il pre-hijacking:
   * - account locale NON verificato: la password (che potrebbe essere dell'attaccante)
   *   viene azzerata e le sessioni invalidate prima di collegare Google;
   * - account locale verificato: Google viene collegato e la password resta valida.
   */
  private async resolveGoogleUser(googleUser: {
    email: string;
    googleId: string;
  }): Promise<User> {
    let user = await this.userService.getUserByEmail(googleUser.email);

    if (!user) {
      const userRole = await this.permissionService.findPermission({
        name: 'USER',
      });
      return this.userService.createUser({
        email: googleUser.email,
        provider: 'google',
        googleId: googleUser.googleId,
        emailVerifiedAt: new Date(),
        permissions: userRole ? [userRole] : [],
      });
    }

    if (!user.emailVerifiedAt) {
      const claimed = await this.userService.claimUnverifiedForGoogle(
        user.id,
        googleUser.googleId,
      );
      if (claimed) {
        await this.authTokenService.invalidateAll(claimed.id);
        return claimed;
      }
      // Verificato nel frattempo dal proprietario: si prosegue con il collegamento normale.
      user = (await this.userService.getUserById(user.id)) ?? user;
    }

    if (!user.googleId) {
      return this.userService.updateUser(user.id, {
        googleId: googleUser.googleId,
        provider: user.password ? 'combined' : 'google',
      });
    }
    if (user.password && user.provider !== 'combined') {
      return this.userService.updateUser(user.id, { provider: 'combined' });
    }
    return user;
  }
}
