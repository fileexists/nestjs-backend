import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpException,
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
import { AuthTokenType } from '../../common/entities/auth-token.entity';
import { User } from '../../common/entities/user.entity';
import {
  RegisterUserDTO,
  UserAuthDTO,
} from '../../common/dto/register-user.dto';
import { GLOBAL_PREFIX } from '../../app.setup';
import { LoginAttemptService } from './login-attempt.service';
import {
  createTrustedDeviceCookie,
  TRUSTED_DEVICE_COOKIE,
  trustedDeviceCookieOptions,
  verifyTrustedDevice,
} from './trusted-device';
import { TokenPayload } from '../../common/interfaces/jwt-payload.interface';

/** Percorso del cookie del refresh token: solo le rotte di autenticazione. */
export const REFRESH_COOKIE_PATH = `/${GLOBAL_PREFIX}/auth`;

/** Tetto ai confronti di riempimento (2^5 - 1): oltre, pareggiare il costo non ha piu' senso. */
const MAX_COST_PADDING_COMPARES = 31;

/** Risposta identica per email nuova ed email gia' registrata (nessun indizio sull'esistenza dell'account). */
export const REGISTRATION_ACCEPTED_MESSAGE =
  'If the address can be registered, an email with the next steps has been sent. Check your inbox.';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly jwtSecret: string;
  private readonly refreshTokenSecret: string;
  private readonly jwtExpiration: string;
  private readonly refreshTokenExpiration: string;
  /** Costo bcrypt (BCRYPT_ROUNDS, default 12). */
  private readonly bcryptRounds: number;
  /** Hash fittizi (uno per costo): per confrontare comunque una password se l'utente non esiste. */
  private readonly dummyHashes = new Map<number, Promise<string>>();
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
    private readonly loginAttemptService: LoginAttemptService,
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
    this.bcryptRounds = Number(
      this.configService.get<number>('BCRYPT_ROUNDS') ?? 12,
    );
    this.reuseGraceMs =
      Number(
        this.configService.get<number>('REFRESH_REUSE_GRACE_SECONDS') ?? 10,
      ) * 1000;
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.bcryptRounds);
  }

  /** Hash di una password casuale al costo indicato (calcolato una volta sola per costo). */
  private getDummyHash(rounds = this.bcryptRounds): Promise<string> {
    let hash = this.dummyHashes.get(rounds);
    if (!hash) {
      hash = bcrypt.hash(randomBytes(24).toString('base64url'), rounds);
      this.dummyHashes.set(rounds, hash);
    }
    return hash;
  }

  /**
   * Un hash piu' economico di quello configurato (account creati prima di alzare BCRYPT_ROUNDS)
   * si verifica molto prima dell'hash fittizio usato per gli indirizzi inesistenti: la differenza
   * di tempo rivelerebbe quali email hanno un account. Si ripete quindi il confronto su un hash
   * fittizio dello stesso costo, fino a pareggiare il lavoro.
   */
  private async equalizeCost(storedHash: string): Promise<void> {
    let rounds: number;
    try {
      rounds = bcrypt.getRounds(storedHash);
    } catch {
      return; // non e' un hash bcrypt: il confronto vero ha gia' fallito subito
    }
    if (rounds >= this.bcryptRounds) return;
    const missing = Math.min(
      2 ** (this.bcryptRounds - rounds) - 1,
      MAX_COST_PADDING_COMPARES,
    );
    const dummy = await this.getDummyHash(rounds);
    for (let i = 0; i < missing; i++) {
      await bcrypt.compare('cost-padding', dummy);
    }
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
    res.clearCookie('refresh_token', { path: REFRESH_COOKIE_PATH });
    // Cookie emessi prima della restrizione di path (D7) vivono ancora su "/".
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
        // Il browser lo invia solo alle rotte /api/auth (refresh, logout), non a ogni API.
        path: REFRESH_COOKIE_PATH,
        maxAge: parseDurationMs(this.refreshTokenExpiration),
      },
    };
  }

  /**
   * Registrazione con risposta UNIFORME (202) per email nuova e gia' registrata: non rivela
   * se un indirizzo ha un account. Per rendere uguali anche i tempi, l'hash bcrypt si calcola
   * sempre. Chi possiede un indirizzo gia' registrato riceve un avviso via email; chi perde una
   * corsa di registrazioni concorrenti (violazione di unicita') viene trattato allo stesso modo.
   * Non si modifica MAI un account esistente (nemmeno la password).
   */
  async register(dto: RegisterUserDTO): Promise<{ message: string }> {
    // Se il permesso USER manca si risponde 503 PRIMA di qualsiasi altra cosa: nessun utente senza permessi.
    const userRole = await this.permissionService.getRequired('USER');
    const hashedPassword = await this.hashPassword(dto.password);

    const existing = await this.userService.getUserByEmail(dto.email);
    if (existing) {
      await this.accountService.sendRegistrationNotice(existing);
      return { message: REGISTRATION_ACCEPTED_MESSAGE };
    }

    try {
      const user = await this.userService.createUser({
        email: dto.email,
        password: hashedPassword,
        permissions: [userRole],
        provider: 'local',
      });
      await this.accountService.sendVerification(user);
    } catch (error) {
      if (!(error instanceof ConflictException)) throw error;
      const winner = await this.userService.getUserByEmail(dto.email);
      if (winner) await this.accountService.sendRegistrationNotice(winner);
    }
    return { message: REGISTRATION_ACCEPTED_MESSAGE };
  }

  /**
   * Login con password. Contro l'enumerazione degli account: la password si confronta SEMPRE
   * con bcrypt (con un hash fittizio se l'utente non esiste o non ha password) e "utente
   * inesistente", "password errata" e "account solo Google" danno la stessa risposta.
   * Blocco per account dopo troppi errori (vedi LoginAttemptService).
   */
  async login(
    dto: UserAuthDTO,
    res: Response,
    trustedDeviceCookie?: string,
  ): Promise<void> {
    const user = await this.userService.getUserByEmail(dto.email);

    // Il tentativo si conta prima di controllare la password (atomico: vedi LoginAttemptService).
    const { locked } = await this.loginAttemptService.registerAttempt(
      dto.email,
    );
    const knownDevice =
      !!user &&
      verifyTrustedDevice(
        this.jwtSecret,
        trustedDeviceCookie,
        user.id,
        user.tokenVersion,
      );
    // Il dispositivo gia' riconosciuto del proprietario non resta fuori per un blocco causato da altri.
    if (locked && !knownDevice) {
      throw new HttpException(
        'Too many failed login attempts. Try again later.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    const hash = user?.password ?? (await this.getDummyHash());
    const matches = await this.comparePasswords(dto.password ?? '', hash);
    if (user?.password) await this.equalizeCost(user.password);
    const valid = !!user?.password && !!dto.password && matches;

    if (!valid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    await this.loginAttemptService.reset(dto.email);

    // Dopo la password corretta: chi la conosce puo' sapere che l'email non e' verificata.
    if (!user.emailVerifiedAt) {
      throw new ForbiddenException(
        'Email not verified. Check your inbox for the verification link.',
      );
    }

    await this.rehashPasswordIfOutdated(user, dto.password as string);

    this.setAuthCookies(
      res,
      await this.generateJwtToken(user),
      await this.generateRefreshToken(user),
    );
    res.cookie(
      TRUSTED_DEVICE_COOKIE,
      createTrustedDeviceCookie(this.jwtSecret, user.id, user.tokenVersion),
      trustedDeviceCookieOptions(
        this.configService.get<string>('NODE_ENV') === 'production',
      ),
    );

    if (user.provider === 'google') {
      await this.userService.updateUser(user.id, { provider: 'combined' });
    }

    res.status(HttpStatus.OK).json({ message: 'Login successful.' });
  }

  /**
   * Conferma l'email scegliendo la password. L'hash si calcola PRIMA di guardare il token, cosi'
   * token valido e non valido costano lo stesso. Chi conferma e' il proprietario della casella:
   * la sua password sostituisce quella inserita alla registrazione (che potrebbe essere di un
   * altro: pre-hijacking).
   */
  async verifyEmail(token: string, password: string): Promise<void> {
    await this.accountService.verifyEmail(
      token,
      await this.hashPassword(password),
    );
  }

  /**
   * Reimposta la password con il token ricevuto via email (monouso, con scadenza).
   * Invalida TUTTE le sessioni (tokenVersion + refresh token), i dispositivi riconosciuti, i token
   * pendenti e il blocco per tentativi falliti. Il token e' consumato in modo atomico.
   */
  async resetPassword(token: string, newPassword: string): Promise<void> {
    const userId = await this.authTokenService.consume(
      token,
      AuthTokenType.PASSWORD_RESET,
    );
    const user = userId ? await this.userService.getUserById(userId) : null;
    if (!userId || !user) {
      throw new BadRequestException('Invalid or expired token');
    }

    await this.userService.resetPassword(
      userId,
      await this.hashPassword(newPassword),
    );
    await this.refreshTokenService.revokeAllForUser(userId);
    await this.authTokenService.invalidateAll(userId);
    await this.loginAttemptService.reset(user.email);
  }

  /** Re-hash trasparente: hash creati con un costo piu' basso dell'attuale vengono rigenerati al login. */
  private async rehashPasswordIfOutdated(
    user: User,
    plainPassword: string,
  ): Promise<void> {
    if (
      !user.password ||
      bcrypt.getRounds(user.password) >= this.bcryptRounds
    ) {
      return;
    }
    try {
      await this.userService.updateUser(user.id, {
        password: await this.hashPassword(plainPassword),
      });
    } catch (error) {
      // Un re-hash fallito non deve impedire l'accesso: si riprovera' al prossimo login.
      this.logger.warn(
        `Re-hash della password non riuscito: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
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
      const userRole = await this.permissionService.getRequired('USER');
      try {
        return await this.userService.createUser({
          email: googleUser.email,
          provider: 'google',
          googleId: googleUser.googleId,
          emailVerifiedAt: new Date(),
          permissions: [userRole],
        });
      } catch (error) {
        if (!(error instanceof ConflictException)) throw error;
        // Due primi accessi contemporanei: l'altro ha vinto la corsa, si prosegue col suo utente.
        user =
          (await this.userService.getUserByGoogleId(googleUser.googleId)) ??
          (await this.userService.getUserByEmail(googleUser.email));
        if (!user) throw error;
        if (user.googleId && user.googleId !== googleUser.googleId) {
          throw new GoogleAuthException(
            'account_conflict',
            'This account is already linked to a different Google account.',
          );
        }
      }
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
