import {
  BadRequestException,
  ForbiddenException,
  HttpStatus,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { randomBytes, randomUUID } from 'crypto';
import { CookieOptions, Response } from 'express';
import type { StringValue } from 'ms';
import { UserService } from '../user/user.service';
import { PermissionService } from '../permission/permission.service';
import { AccountService } from './account.service';
import { AuthTokenService } from './auth-token.service';
import { RefreshTokenService } from './refresh-token.service';
import { parseDurationMs } from '../../common/utils/duration';
import { GoogleAuthException } from './google-auth.exception';
import { User } from '../../common/entities/user.entity';
import { UserAuthDTO } from '../../common/dto/register-user.dto';
import { TokenPayload } from '../../common/interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly jwtSecret: string;
  private readonly refreshTokenSecret: string;
  private readonly jwtExpiration: string;
  private readonly refreshTokenExpiration: string;
  /** Tolleranza (ms) per il riuso di un refresh token appena ruotato (richieste parallele). 0 = nessuna. */
  private readonly reuseGraceMs: number;

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly permissionService: PermissionService,
    private readonly authTokenService: AuthTokenService,
    private readonly accountService: AccountService,
    private readonly refreshTokenService: RefreshTokenService,
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
    this.reuseGraceMs =
      Number(
        this.configService.get<number>('REFRESH_REUSE_GRACE_SECONDS') ?? 0,
      ) * 1000;
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

  /** Access token: porta `tokenVersion`, cosi' logout-all, reuse e reset password lo invalidano subito. */
  async generateJwtToken(user: TokenPayload): Promise<string> {
    return this.jwtService.signAsync(
      {
        id: user.id,
        email: user.email,
        tokenVersion: user.tokenVersion ?? 0,
      },
      { secret: this.jwtSecret, expiresIn: this.jwtExpiration as StringValue },
    );
  }

  /**
   * Emette un refresh token e lo registra in `refresh_tokens` (solo l'hash del jti).
   * Senza `familyId` inizia una nuova sessione (login); alla rotazione si passa
   * quello della sessione esistente.
   */
  async generateRefreshToken(
    user: TokenPayload,
    familyId: string = randomUUID(),
  ): Promise<string> {
    const jti = randomBytes(32).toString('base64url');
    const token = await this.jwtService.signAsync(
      {
        id: user.id,
        email: user.email,
        tokenVersion: user.tokenVersion ?? 0,
        fid: familyId,
      },
      {
        secret: this.refreshTokenSecret,
        expiresIn: this.refreshTokenExpiration as StringValue,
        jwtid: jti,
      },
    );
    await this.refreshTokenService.create({
      userId: user.id as string,
      jti,
      familyId,
      expiresAt: new Date(
        Date.now() + parseDurationMs(this.refreshTokenExpiration),
      ),
    });
    return token;
  }

  async verifyJwtToken(token: string | undefined): Promise<TokenPayload> {
    try {
      if (!token) throw new Error('No token provided');
      const payload = await this.jwtService.verifyAsync<TokenPayload>(token, {
        secret: this.jwtSecret,
      });
      await this.assertSessionCurrent(payload);
      return payload;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  /**
   * Un access token firmato correttamente vale solo finche' la sessione e' quella
   * attuale: se l'utente non esiste piu' o `tokenVersion` e' cambiato (logout-all,
   * reuse detection, reset password) il token e' rifiutato subito, senza aspettare la scadenza.
   */
  async assertSessionCurrent(payload: TokenPayload): Promise<void> {
    const state = payload.id
      ? await this.userService.getAuthState(payload.id)
      : null;
    if (
      !state ||
      payload.tokenVersion === undefined ||
      payload.tokenVersion !== state.tokenVersion
    ) {
      throw new UnauthorizedException('User is not authenticated.');
    }
  }

  /**
   * Rotazione: il refresh token presentato viene marcato come usato e ne esce
   * uno nuovo della stessa famiglia. Se arriva un token GIA' usato (furto/replay)
   * si revoca l'intera famiglia e si invalidano le sessioni dell'utente.
   */
  async refreshTokens(
    refreshToken: string,
  ): Promise<{ token: string; refreshToken: string }> {
    const invalid = () =>
      new UnauthorizedException('Invalid or expired refresh token');

    try {
      const decoded = await this.jwtService.verifyAsync<TokenPayload>(
        refreshToken,
        { secret: this.refreshTokenSecret },
      );
      // Un refresh token senza jti/fid e' di prima della rotazione: non e' piu' valido.
      if (!decoded.id || !decoded.jti || !decoded.fid) throw invalid();

      const rotation = await this.refreshTokenService.rotate(decoded.jti);
      if (rotation.status === 'reused') {
        const usedAt = rotation.token.usedAt?.getTime() ?? 0;
        if (Date.now() - usedAt >= this.reuseGraceMs) {
          await this.refreshTokenService.revokeFamily(rotation.token.familyId);
          await this.userService.incrementTokenVersion(rotation.token.userId);
          this.logger.warn(
            `Riuso di un refresh token rilevato (utente ${rotation.token.userId}): famiglia revocata e sessioni invalidate`,
          );
        }
        throw invalid();
      }
      if (rotation.status !== 'rotated') throw invalid();

      const user = await this.userService.getUserById(decoded.id);
      if (
        !user ||
        user.id !== rotation.token.userId ||
        (decoded.tokenVersion ?? 0) !== user.tokenVersion
      ) {
        throw invalid();
      }

      const newAccessToken = await this.generateJwtToken(user);
      const newRefreshToken = await this.generateRefreshToken(
        user,
        rotation.token.familyId,
      );
      return { token: newAccessToken, refreshToken: newRefreshToken };
    } catch (error) {
      if (!(error instanceof UnauthorizedException)) {
        this.logger.error(
          `Refresh fallito: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      throw invalid();
    }
  }

  /** Revoca TUTTE le sessioni dell'utente: refresh token e access token gia' emessi. */
  async revokeSessions(userId: string): Promise<void> {
    await this.userService.incrementTokenVersion(userId);
    await this.refreshTokenService.revokeAllForUser(userId);
  }

  /**
   * Logout: revoca la sessione del refresh token corrente (non solo i cookie).
   * Un cookie assente o non valido non e' un errore: non c'e' nulla da revocare.
   */
  async logout(refreshToken: string | undefined): Promise<void> {
    if (!refreshToken) return;
    try {
      // Anche un token scaduto identifica la sessione da chiudere; la firma resta verificata.
      const decoded = await this.jwtService.verifyAsync<TokenPayload>(
        refreshToken,
        { secret: this.refreshTokenSecret, ignoreExpiration: true },
      );
      if (decoded.fid) {
        await this.refreshTokenService.revokeFamily(decoded.fid);
      }
    } catch {
      // cookie non valido: nessuna sessione da revocare
    }
  }

  setAuthCookies(res: Response, accessToken: string, refreshToken: string) {
    const { accessTokenOptions, refreshTokenOptions } = this.getCookieOptions();
    res.cookie('access_token', accessToken, accessTokenOptions);
    res.cookie('refresh_token', refreshToken, refreshTokenOptions);
  }

  clearAuthCookies(res: Response): void {
    res.clearCookie('access_token', { path: '/' });
    res.clearCookie('refresh_token', { path: '/' });
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

    this.setAuthCookies(
      res,
      await this.generateJwtToken(user),
      await this.generateRefreshToken(user),
    );

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

    this.setAuthCookies(
      res,
      await this.generateJwtToken(user),
      await this.generateRefreshToken(user),
    );
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
    // L'identita' Google (sub) prevale sull'email: l'utente puo' cambiare email su Google.
    let user = await this.userService.getUserByGoogleId(googleUser.googleId);
    if (!user) {
      user = await this.userService.getUserByEmail(googleUser.email);
      // Stessa email ma un altro account Google: non si entra e non si sovrascrive nulla.
      if (user?.googleId && user.googleId !== googleUser.googleId) {
        throw new GoogleAuthException(
          'account_conflict',
          'This account is already linked to a different Google account.',
        );
      }
    }

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
