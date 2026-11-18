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
import { RefreshResultCache } from './refresh-result-cache';
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

/** Path of the refresh token cookie: only the authentication routes. */
export const REFRESH_COOKIE_PATH = `/${GLOBAL_PREFIX}/auth`;

/** Cap on the padding compares (2^5 - 1): beyond that, equalizing the cost no longer makes sense. */
const MAX_COST_PADDING_COMPARES = 31;

/** Identical response for a new and an already registered email (no hint about whether the account exists). */
export const REGISTRATION_ACCEPTED_MESSAGE =
  'If the address can be registered, an email with the next steps has been sent. Check your inbox.';

/** The pair of tokens a rotation hands out. */
export interface RefreshedTokens {
  token: string;
  refreshToken: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly jwtSecret: string;
  private readonly refreshTokenSecret: string;
  private readonly jwtExpiration: string;
  private readonly refreshTokenExpiration: string;
  /** bcrypt cost (BCRYPT_ROUNDS, default 12). */
  private readonly bcryptRounds: number;
  /** Dummy hashes (one per cost): to compare a password anyway when the user does not exist. */
  private readonly dummyHashes = new Map<number, Promise<string>>();
  /** Tolerance (s) for reusing a refresh token that was just rotated (parallel requests). 0 = none. */
  private readonly reuseGraceSeconds: number;
  /**
   * The pair issued by each rotation, kept for the grace period so that a second use of the same
   * refresh token gets the same tokens instead of a 401. Per process: with several instances a
   * request that lands on another one is only rejected (never treated as theft inside the grace).
   */
  private readonly rotations: RefreshResultCache<RefreshedTokens>;

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
    this.reuseGraceSeconds = Number(
      this.configService.get<number>('REFRESH_REUSE_GRACE_SECONDS') ?? 10,
    );
    this.rotations = new RefreshResultCache(this.reuseGraceSeconds * 1000);
  }

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.bcryptRounds);
  }

  /** Hash of a random password at the given cost (computed only once per cost). */
  private getDummyHash(rounds = this.bcryptRounds): Promise<string> {
    let hash = this.dummyHashes.get(rounds);
    if (!hash) {
      hash = bcrypt.hash(randomBytes(24).toString('base64url'), rounds);
      this.dummyHashes.set(rounds, hash);
    }
    return hash;
  }

  /**
   * A hash cheaper than the configured one (accounts created before BCRYPT_ROUNDS was raised)
   * is verified much sooner than the dummy hash used for non-existent addresses: the time
   * difference would reveal which emails have an account. So the compare is repeated on a
   * dummy hash of the same cost, until the work is evened out.
   */
  private async equalizeCost(storedHash: string): Promise<void> {
    let rounds: number;
    try {
      rounds = bcrypt.getRounds(storedHash);
    } catch {
      return; // not a bcrypt hash: the real compare has already failed immediately
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

  /**
   * Access token: carries `tokenVersion` (logout-all, reuse and password reset invalidate it immediately)
   * and `fid`, the session family (logging out of a single device revokes that family).
   */
  async generateJwtToken(
    user: TokenPayload,
    familyId: string,
  ): Promise<string> {
    return this.jwtService.signAsync(
      {
        id: user.id,
        email: user.email,
        tokenVersion: user.tokenVersion ?? 0,
        fid: familyId,
      },
      { secret: this.jwtSecret, expiresIn: this.jwtExpiration as StringValue },
    );
  }

  /**
   * Issues a refresh token and records it in `refresh_tokens` (only the hash of the jti).
   * Without `familyId` it starts a new session (login); on rotation the one of the
   * existing session is passed in.
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
   * A correctly signed access token is only valid while the session is the current one:
   * its family (`fid`) must belong to the user, not be revoked and not be expired, and `tokenVersion`
   * must match. So logout (of one device or all), reuse detection and password reset
   * invalidate it immediately, without waiting for it to expire. A token without `fid` (issued
   * before this check) is rejected: a refresh is enough to get a new one. A single query.
   */
  async assertSessionCurrent(payload: TokenPayload): Promise<void> {
    const session =
      payload.id && payload.fid
        ? await this.refreshTokenService.findActiveSession(
            payload.id,
            payload.fid,
          )
        : null;
    if (
      !session ||
      payload.tokenVersion === undefined ||
      payload.tokenVersion !== session.tokenVersion
    ) {
      throw new UnauthorizedException('User is not authenticated.');
    }
  }

  /**
   * Rotation: the presented refresh token is marked as used and a new one of the same
   * family comes out. Parallel requests with the same token (several tabs, many API calls after
   * the access token expired) get the SAME pair: inside the grace period a second use is answered
   * from memory, not with an error. Past it, an ALREADY used token (theft/replay) revokes the whole
   * family and invalidates the user's sessions.
   */
  async refreshTokens(refreshToken: string): Promise<RefreshedTokens> {
    const invalid = () =>
      new UnauthorizedException('Invalid or expired refresh token');

    try {
      const decoded = await this.jwtService.verifyAsync<TokenPayload>(
        refreshToken,
        { secret: this.refreshTokenSecret },
      );
      // A refresh token without jti/fid predates rotation: it is no longer valid.
      if (!decoded.id || !decoded.jti || !decoded.fid) throw invalid();

      // Look up and register without awaiting in between: two concurrent requests with the same
      // token cannot both start a rotation, the second one waits for the first one's result.
      const inProgress = this.rotations.get(decoded.jti);
      if (inProgress) return await inProgress;

      const rotation = this.rotate(decoded.id, decoded.jti, decoded);
      this.rotations.set(decoded.jti, rotation, {
        familyId: decoded.fid,
        userId: decoded.id,
      });
      // A failure is never cached: the next attempt is judged again.
      rotation.catch(() => this.rotations.delete(decoded.jti as string));
      return await rotation;
    } catch (error) {
      if (!(error instanceof UnauthorizedException)) {
        this.logger.error(
          `Refresh failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      throw invalid();
    }
  }

  private async rotate(
    userId: string,
    jti: string,
    decoded: TokenPayload,
  ): Promise<RefreshedTokens> {
    const invalid = () =>
      new UnauthorizedException('Invalid or expired refresh token');

    const rotation = await this.refreshTokenService.rotate(
      jti,
      this.reuseGraceSeconds,
    );
    if (rotation.status === 'reused') {
      // Inside the grace period (by the database clock) it is a parallel request whose result is
      // not in this process's memory: reject it, do not punish it. After it, it is a replay.
      if (!rotation.withinGrace) {
        const { familyId, userId: owner } = rotation.token;
        this.rotations.invalidateFamily(familyId);
        await this.refreshTokenService.revokeFamily(familyId);
        await this.userService.incrementTokenVersion(owner);
        this.logger.warn(
          `Refresh token reuse detected (user ${owner}): family revoked and sessions invalidated`,
        );
      }
      throw invalid();
    }
    if (rotation.status !== 'rotated') throw invalid();

    const user = await this.userService.getUserById(userId);
    if (
      !user ||
      user.id !== rotation.token.userId ||
      (decoded.tokenVersion ?? 0) !== user.tokenVersion
    ) {
      throw invalid();
    }

    const familyId = rotation.token.familyId;
    return {
      token: await this.generateJwtToken(user, familyId),
      refreshToken: await this.generateRefreshToken(user, familyId),
    };
  }

  /** Revokes ALL the user's sessions: refresh tokens and already issued access tokens. */
  async revokeSessions(userId: string): Promise<void> {
    this.rotations.invalidateUser(userId);
    await this.userService.incrementTokenVersion(userId);
    await this.refreshTokenService.revokeAllForUser(userId);
  }

  /**
   * Logout: revokes the session of the current refresh token (not just the cookies).
   * A missing or invalid cookie is not an error: there is nothing to revoke.
   */
  async logout(refreshToken: string | undefined): Promise<void> {
    if (!refreshToken) return;
    try {
      // Even an expired token identifies the session to close; the signature is still verified.
      const decoded = await this.jwtService.verifyAsync<TokenPayload>(
        refreshToken,
        { secret: this.refreshTokenSecret, ignoreExpiration: true },
      );
      if (decoded.fid) {
        this.rotations.invalidateFamily(decoded.fid);
        await this.refreshTokenService.revokeFamily(decoded.fid);
      }
    } catch {
      // invalid cookie: no session to revoke
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
    // Cookies issued before the path restriction (D7) still live on "/".
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
        // The browser only sends it to the /api/auth routes (refresh, logout), not to every API.
        path: REFRESH_COOKIE_PATH,
        maxAge: parseDurationMs(this.refreshTokenExpiration),
      },
    };
  }

  /**
   * Registration with a UNIFORM response (202) for a new and an already registered email: it does not reveal
   * whether an address has an account. To make the timings equal as well, the bcrypt hash is
   * always computed. Whoever owns an already registered address gets a notice by email; whoever loses a
   * race between concurrent registrations (uniqueness violation) is treated the same way.
   * An existing account is NEVER modified (not even its password).
   */
  async register(dto: RegisterUserDTO): Promise<{ message: string }> {
    // If the USER permission is missing, answer 503 BEFORE anything else: no user without permissions.
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
   * Login with password. Against account enumeration: the password is ALWAYS compared
   * with bcrypt (with a dummy hash if the user does not exist or has no password) and "non-existent
   * user", "wrong password" and "Google-only account" give the same response.
   * Per-account lock after too many failures (see LoginAttemptService).
   */
  async login(
    dto: UserAuthDTO,
    res: Response,
    trustedDeviceCookie?: string,
  ): Promise<void> {
    const user = await this.userService.getUserByEmail(dto.email);

    // The attempt is counted before checking the password (atomic: see LoginAttemptService).
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
    // The owner's already recognized device is not shut out by a lock caused by others.
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

    // After the correct password: whoever knows it may learn that the email is not verified.
    if (!user.emailVerifiedAt) {
      throw new ForbiddenException(
        'Email not verified. Check your inbox for the verification link.',
      );
    }

    await this.rehashPasswordIfOutdated(user, dto.password as string);

    await this.startSession(user, res);
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
   * Confirms the email while choosing the password. The hash is computed BEFORE looking at the token, so
   * a valid and an invalid token cost the same. Whoever confirms owns the mailbox:
   * their password replaces the one entered at registration (which may belong to someone
   * else: pre-hijacking).
   */
  async verifyEmail(token: string, password: string): Promise<void> {
    await this.accountService.verifyEmail(
      token,
      await this.hashPassword(password),
    );
  }

  /**
   * Resets the password with the token received by email (single-use, with an expiry).
   * Invalidates ALL the sessions (tokenVersion + refresh tokens), the recognized devices, the pending
   * tokens and the lock from failed attempts. The token is consumed atomically.
   * The hash is computed BEFORE consuming the token: if it fails the link is not burned (and a valid
   * and an invalid token cost the same).
   */
  async resetPassword(token: string, newPassword: string): Promise<void> {
    const passwordHash = await this.hashPassword(newPassword);
    const userId = await this.authTokenService.consume(
      token,
      AuthTokenType.PASSWORD_RESET,
    );
    const user = userId ? await this.userService.getUserById(userId) : null;
    if (!userId || !user) {
      throw new BadRequestException('Invalid or expired token');
    }

    this.rotations.invalidateUser(userId);
    await this.userService.resetPassword(userId, passwordHash);
    await this.refreshTokenService.revokeAllForUser(userId);
    await this.authTokenService.invalidateAll(userId);
    await this.loginAttemptService.reset(user.email);
  }

  /** Transparent re-hash: hashes created with a lower cost than the current one are regenerated at login. */
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
      // A failed re-hash must not prevent access: it will be retried at the next login.
      this.logger.warn(
        `Password re-hash failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  async handleGoogleCallback(
    googleUser: { email: string; googleId: string },
    res: Response,
  ): Promise<void> {
    const user = await this.resolveGoogleUser(googleUser);
    await this.startSession(user, res);
  }

  /** New session: a new family, shared by the access and refresh token, in the cookies. */
  private async startSession(user: User, res: Response): Promise<void> {
    const familyId = randomUUID();
    this.setAuthCookies(
      res,
      await this.generateJwtToken(user, familyId),
      await this.generateRefreshToken(user, familyId),
    );
  }

  /**
   * Finds or creates the user for a Google profile whose email Google has ALREADY verified
   * (guaranteed by the strategy). Rules against pre-hijacking:
   * - UNVERIFIED local account: the password (which may be the attacker's)
   *   is wiped and the sessions are invalidated before linking Google;
   * - verified local account: Google is linked and the password stays valid.
   */
  private async resolveGoogleUser(googleUser: {
    email: string;
    googleId: string;
  }): Promise<User> {
    // The Google identity (sub) takes precedence over the email: the user may change email on Google.
    let user = await this.userService.getUserByGoogleId(googleUser.googleId);
    if (!user) {
      user = await this.userService.getUserByEmail(googleUser.email);
      // Same email but another Google account: do not log in and overwrite nothing.
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
        // Two simultaneous first logins: the other one won the race, carry on with their user.
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
      // Verified in the meantime by the owner: carry on with the normal linking.
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
