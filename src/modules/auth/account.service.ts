import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthTokenType } from '../../common/entities/auth-token.entity';
import { parseDurationMs } from '../../common/utils/duration';
import { MailService } from '../mail/mail.service';
import { UserService } from '../user/user.service';
import { AuthTokenService } from './auth-token.service';

const DEFAULT_EMAIL_VERIFICATION_TTL = '24h';
/** Tra un invio e il successivo per lo stesso account. */
export const RESEND_COOLDOWN_MS = 60_000;

/** Verifica dell'email e relativo reinvio. */
@Injectable()
export class AccountService {
  private readonly logger = new Logger(AccountService.name);
  private readonly verificationTtlMs: number;

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
    sending.catch((error: unknown) => {
      this.logger.error(
        `Invio email fallito: ${error instanceof Error ? error.message : String(error)}`,
      );
    });
  }
}
