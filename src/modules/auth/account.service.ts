import {
  BadRequestException,
  Injectable,
  Logger,
  OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthTokenType } from '../../common/entities/auth-token.entity';
import { parseDurationMs } from '../../common/utils/duration';
import { MailService } from '../mail/mail.service';
import { UserService } from '../user/user.service';
import { AuthTokenService } from './auth-token.service';

const DEFAULT_EMAIL_VERIFICATION_TTL = '24h';
const DEFAULT_PASSWORD_RESET_TTL = '1h';
/** Between one send and the next for the same account. */
export const RESEND_COOLDOWN_MS = 60_000;
/** At most one "address already registered" notice every 10 minutes for the same mailbox. */
export const NOTICE_COOLDOWN_MS = 10 * 60_000;
/** How long shutdown waits for the emails still being sent. */
export const SHUTDOWN_DRAIN_TIMEOUT_MS = 20_000;

/** Email verification and its resend. */
@Injectable()
export class AccountService implements OnApplicationShutdown {
  private readonly logger = new Logger(AccountService.name);
  private readonly verificationTtlMs: number;
  private readonly passwordResetTtlMs: number;
  /** Jobs running outside the HTTP request cycle (see runInBackground). */
  private readonly background = new Set<Promise<void>>();

  constructor(
    private readonly userService: UserService,
    private readonly authTokenService: AuthTokenService,
    private readonly mailService: MailService,
    configService: ConfigService,
  ) {
    this.verificationTtlMs =
      parseDurationMs(
        configService.get<string>('EMAIL_VERIFICATION_TTL') ??
          DEFAULT_EMAIL_VERIFICATION_TTL,
      ) || parseDurationMs(DEFAULT_EMAIL_VERIFICATION_TTL);
    this.passwordResetTtlMs =
      parseDurationMs(
        configService.get<string>('PASSWORD_RESET_TTL') ??
          DEFAULT_PASSWORD_RESET_TTL,
      ) || parseDurationMs(DEFAULT_PASSWORD_RESET_TTL);
  }

  /**
   * Runs a job WITHOUT making the HTTP request wait for it. Needed by the endpoints with a
   * uniform response (resend verification, password reset): if the response waited for the database
   * and the email, the timings would reveal whether the address has an account. Errors are only logged.
   */
  runInBackground(task: () => Promise<void>): void {
    // setImmediate: the job starts AFTER the response has been written; with a plain
    // microtask the queries for an existing account would run first and would delay (slightly,
    // but measurably) the response compared to an unknown address.
    const run: Promise<void> = new Promise<void>((resolve) =>
      setImmediate(resolve),
    )
      .then(task)
      .catch((error: unknown) => {
        this.logger.error(
          `Background operation failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      })
      .finally(() => {
        this.background.delete(run);
      });
    this.background.add(run);
  }

  /**
   * Waits for the background jobs in progress (graceful shutdown and tests). With `timeoutMs` it
   * gives up after that long, logging how many jobs were left, so a hung SMTP cannot hold the
   * shutdown forever.
   */
  async drain(timeoutMs?: number): Promise<void> {
    const finished = (async () => {
      while (this.background.size > 0) {
        await Promise.allSettled([...this.background]);
      }
    })();
    if (timeoutMs === undefined) return finished;

    let timer: NodeJS.Timeout | undefined;
    const outcome = await Promise.race([
      finished.then(() => 'done' as const),
      new Promise<'timeout'>((resolve) => {
        timer = setTimeout(() => resolve('timeout'), timeoutMs);
      }),
    ]);
    clearTimeout(timer);
    if (outcome === 'timeout') {
      this.logger.warn(
        `Shutdown: ${this.background.size} background operations did not finish within ${timeoutMs} ms (unsent emails are lost)`,
      );
    }
  }

  /**
   * On SIGTERM/SIGINT (`enableShutdownHooks` in main.ts) let the emails already queued go out
   * before the process exits. There is no persistent queue: an email that is still failing after
   * the retries, or that is in flight when the process is killed, is lost.
   */
  async onApplicationShutdown(): Promise<void> {
    await this.drain(SHUTDOWN_DRAIN_TIMEOUT_MS);
  }

  queueResendVerification(email: string): void {
    this.runInBackground(() => this.resendVerification(email));
  }

  queuePasswordReset(email: string): void {
    this.runInBackground(() => this.requestPasswordReset(email));
  }

  /**
   * Sends the password reset link. It never reveals whether the address exists: for
   * non-existent or too recent accounts nothing happens. It also works for unverified accounts
   * (the reset proves ownership of the mailbox) and Google-only ones (they will be able to set a password).
   */
  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.userService.getUserByEmail(email);
    if (!user) return;

    const latest = await this.authTokenService.findLatestActive(
      user.id,
      AuthTokenType.PASSWORD_RESET,
    );
    if (
      latest &&
      Date.now() - latest.createdAt.getTime() < RESEND_COOLDOWN_MS
    ) {
      return;
    }
    const token = await this.authTokenService.issue(
      user.id,
      AuthTokenType.PASSWORD_RESET,
      this.passwordResetTtlMs,
    );
    this.dispatch(this.mailService.sendPasswordResetEmail(user.email, token));
  }

  /**
   * Creates a verification token and sends the email. The send is NOT awaited: the HTTP
   * response must not depend on SMTP latency or errors (otherwise the
   * timings would reveal whether the address exists); an error is only logged.
   */
  async sendVerification(user: { id: string; email: string }): Promise<void> {
    const token = await this.authTokenService.issue(
      user.id,
      AuthTokenType.EMAIL_VERIFICATION,
      this.verificationTtlMs,
    );
    this.dispatch(this.mailService.sendVerificationEmail(user.email, token));
  }

  /**
   * Someone tried to register an address that already has an account: the HTTP response
   * is identical to that of a new registration, so whoever owns the mailbox is
   * notified by email. Frequency is limited so someone else's mailbox cannot be flooded.
   */
  async sendRegistrationNotice(user: {
    id: string;
    email: string;
  }): Promise<void> {
    const latest = await this.authTokenService.findLatestActive(
      user.id,
      AuthTokenType.REGISTRATION_NOTICE,
    );
    if (
      latest &&
      Date.now() - latest.createdAt.getTime() < NOTICE_COOLDOWN_MS
    ) {
      return;
    }
    await this.authTokenService.issue(
      user.id,
      AuthTokenType.REGISTRATION_NOTICE,
      NOTICE_COOLDOWN_MS,
    );
    this.dispatch(this.mailService.sendRegistrationNotice(user.email));
  }

  /**
   * Confirms the email with the single-use token and sets the chosen (already hashed) password.
   * The token is consumed in any case; if the account was already verified nothing changes.
   */
  async verifyEmail(token: string, passwordHash: string): Promise<void> {
    const userId = await this.authTokenService.consume(
      token,
      AuthTokenType.EMAIL_VERIFICATION,
    );
    if (
      !userId ||
      !(await this.userService.activateWithPassword(userId, passwordHash))
    ) {
      throw new BadRequestException('Invalid or expired token');
    }
  }

  /**
   * Resends the verification email. It never reveals whether the address exists: for
   * non-existent, already verified or too recent accounts nothing happens.
   */
  async resendVerification(email: string): Promise<void> {
    const user = await this.userService.getUserByEmail(email);
    if (!user || user.emailVerifiedAt || !user.password) return;

    const latest = await this.authTokenService.findLatestActive(
      user.id,
      AuthTokenType.EMAIL_VERIFICATION,
    );
    if (
      latest &&
      Date.now() - latest.createdAt.getTime() < RESEND_COOLDOWN_MS
    ) {
      return;
    }
    await this.sendVerification(user);
  }

  private dispatch(sending: Promise<void>): void {
    this.runInBackground(() => sending);
  }
}
