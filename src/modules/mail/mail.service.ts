import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { parseFrontendUrls } from '../../common/utils/frontend-url';
import { parseDurationMs } from '../../common/utils/duration';
import {
  MailContent,
  passwordResetEmail,
  registrationNoticeEmail,
  verificationEmail,
} from './mail.templates';

const DEFAULT_EMAIL_VERIFICATION_TTL = '24h';
const DEFAULT_PASSWORD_RESET_TTL = '1h';

/** Attese tra un tentativo e il successivo: 3 tentativi in tutto. */
export const MAIL_RETRY_DELAYS_MS = [2_000, 10_000];

/** Errori di rete o risposte 4xx dell'SMTP: ha senso riprovare. Il resto (5xx, auth) no. */
const TRANSIENT_CODES = new Set([
  'ETIMEDOUT',
  'ECONNECTION',
  'ECONNRESET',
  'ECONNREFUSED',
  'ESOCKET',
  'EPIPE',
  'EDNS',
]);

export function isTransientMailError(error: unknown): boolean {
  const { code, responseCode } = (error ?? {}) as {
    code?: unknown;
    responseCode?: unknown;
  };
  if (typeof code === 'string' && TRANSIENT_CODES.has(code)) return true;
  return (
    typeof responseCode === 'number' &&
    responseCode >= 400 &&
    responseCode < 500
  );
}

/**
 * Invio email via SMTP (SMTP_HOST/SMTP_PORT; in sviluppo Mailpit su mailpit:1025).
 * I link puntano SEMPRE al frontend configurato (prima origine di FRONTEND_URL):
 * il frontend legge il token e chiama l'API in POST, cosi' gli scanner di posta
 * che aprono i link in GET non consumano il token monouso.
 */
@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private readonly transporter: Transporter;
  private readonly from: string;
  private readonly frontendUrl: string;
  private readonly verificationTtlMs: number;
  private readonly passwordResetTtlMs: number;

  constructor(private readonly configService: ConfigService) {
    const user = this.configService.get<string>('SMTP_USER');
    const pass = this.configService.get<string>('SMTP_PASS');

    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('SMTP_HOST') ?? 'localhost',
      port: Number(this.configService.get<number>('SMTP_PORT') ?? 1025),
      secure: this.configService.get<boolean>('SMTP_SECURE') ?? false,
      auth: user ? { user, pass: pass ?? '' } : undefined,
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 20_000,
    });

    this.from =
      this.configService.get<string>('MAIL_FROM') ??
      'Auth <no-reply@localhost>';
    this.frontendUrl = parseFrontendUrls(
      this.configService.get<string>('FRONTEND_URL') ?? 'http://localhost:3000',
    )[0];
    this.verificationTtlMs =
      parseDurationMs(
        this.configService.get<string>('EMAIL_VERIFICATION_TTL') ??
          DEFAULT_EMAIL_VERIFICATION_TTL,
      ) || parseDurationMs(DEFAULT_EMAIL_VERIFICATION_TTL);
    this.passwordResetTtlMs =
      parseDurationMs(
        this.configService.get<string>('PASSWORD_RESET_TTL') ??
          DEFAULT_PASSWORD_RESET_TTL,
      ) || parseDurationMs(DEFAULT_PASSWORD_RESET_TTL);
  }

  async sendVerificationEmail(to: string, token: string): Promise<void> {
    const link = `${this.frontendUrl}/verify-email?token=${encodeURIComponent(token)}`;
    await this.send(to, verificationEmail(link, this.verificationTtlMs));
  }

  async sendPasswordResetEmail(to: string, token: string): Promise<void> {
    const link = `${this.frontendUrl}/reset-password?token=${encodeURIComponent(token)}`;
    await this.send(to, passwordResetEmail(link, this.passwordResetTtlMs));
  }

  /** Avviso a chi possiede l'indirizzo: qualcuno ha provato a registrarlo di nuovo. */
  async sendRegistrationNotice(to: string): Promise<void> {
    await this.send(
      to,
      registrationNoticeEmail(
        `${this.frontendUrl}/login`,
        `${this.frontendUrl}/forgot-password`,
      ),
    );
  }

  private async send(to: string, content: MailContent): Promise<void> {
    const message = {
      from: this.from,
      to,
      subject: content.subject,
      text: content.text,
      html: content.html,
    };
    for (let attempt = 0; ; attempt++) {
      try {
        await this.transporter.sendMail(message);
        this.logger.log(`Email "${content.subject}" inviata`);
        return;
      } catch (error) {
        const delay = MAIL_RETRY_DELAYS_MS[attempt];
        if (delay === undefined || !isTransientMailError(error)) throw error;
        this.logger.warn(
          `Invio email non riuscito (${error instanceof Error ? error.message : String(error)}), riprovo tra ${delay / 1000}s`,
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }
}
