import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthTokenType } from '../../common/entities/auth-token.entity';
import { parseDurationMs } from '../../common/utils/duration';
import { MailService } from '../mail/mail.service';
import { UserService } from '../user/user.service';
import { AuthTokenService } from './auth-token.service';

const DEFAULT_EMAIL_VERIFICATION_TTL = '24h';
const DEFAULT_PASSWORD_RESET_TTL = '1h';
/** Tra un invio e il successivo per lo stesso account. */
export const RESEND_COOLDOWN_MS = 60_000;
/** Al massimo un avviso "indirizzo gia' registrato" ogni 10 minuti per la stessa casella. */
export const NOTICE_COOLDOWN_MS = 10 * 60_000;

/** Verifica dell'email e relativo reinvio. */
@Injectable()
export class AccountService {
  private readonly logger = new Logger(AccountService.name);
  private readonly verificationTtlMs: number;
  private readonly passwordResetTtlMs: number;
  /** Lavori in corso fuori dal ciclo della richiesta HTTP (vedi runInBackground). */
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
   * Esegue un lavoro SENZA farlo aspettare alla richiesta HTTP. Serve agli endpoint a risposta
   * uniforme (reinvio verifica, reset password): se la risposta aspettasse database ed email, i
   * tempi rivelerebbero se l'indirizzo ha un account. Gli errori vengono solo loggati.
   */
  runInBackground(task: () => Promise<void>): void {
    // setImmediate: il lavoro parte DOPO che la risposta e' stata scritta; con un semplice
    // microtask le query dell'account esistente girerebbero prima e ritarderebbero (di poco,
    // ma in modo misurabile) la risposta rispetto a un indirizzo sconosciuto.
    const run: Promise<void> = new Promise<void>((resolve) =>
      setImmediate(resolve),
    )
      .then(task)
      .catch((error: unknown) => {
        this.logger.error(
          `Operazione in background fallita: ${error instanceof Error ? error.message : String(error)}`,
        );
      })
      .finally(() => {
        this.background.delete(run);
      });
    this.background.add(run);
  }

  /** Attende i lavori in background in corso (spegnimento ordinato e test). */
  async drain(): Promise<void> {
    while (this.background.size > 0) {
      await Promise.allSettled([...this.background]);
    }
  }

  queueResendVerification(email: string): void {
    this.runInBackground(() => this.resendVerification(email));
  }

  queuePasswordReset(email: string): void {
    this.runInBackground(() => this.requestPasswordReset(email));
  }

  /**
   * Invia il link di reset password. Non rivela mai se l'indirizzo esiste: per account
   * inesistenti o troppo recenti non succede nulla. Vale anche per account non verificati
   * (il reset dimostra il possesso della casella) e solo-Google (potranno impostare una password).
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
   * Crea un token di verifica e invia l'email. L'invio NON e' atteso: la risposta
   * HTTP non deve dipendere dalla latenza o dagli errori dell'SMTP (altrimenti
   * i tempi rivelerebbero se l'indirizzo esiste); un errore viene solo loggato.
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
   * Qualcuno ha provato a registrare un indirizzo che ha gia' un account: la risposta HTTP
   * e' identica a quella di una registrazione nuova, quindi chi possiede la casella viene
   * avvisato per email. Frequenza limitata per non poter inondare la casella di un altro.
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

  async verifyEmail(token: string): Promise<void> {
    const userId = await this.authTokenService.consume(
      token,
      AuthTokenType.EMAIL_VERIFICATION,
    );
    if (!userId) {
      throw new BadRequestException('Invalid or expired token');
    }
    await this.userService.markEmailVerified(userId);
  }

  /**
   * Reinvia l'email di verifica. Non rivela mai se l'indirizzo esiste: per
   * account inesistenti, gia' verificati o troppo recenti non succede nulla.
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
