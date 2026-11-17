import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { parseFrontendUrls } from '../../common/utils/frontend-url';
import { parseDurationMs } from '../../common/utils/duration';
import {
  MailContent,
  registrationNoticeEmail,
  verificationEmail,
} from './mail.templates';

const DEFAULT_EMAIL_VERIFICATION_TTL = '24h';

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
  }

  async sendVerificationEmail(to: string, token: string): Promise<void> {
    const link = `${this.frontendUrl}/verify-email?token=${encodeURIComponent(token)}`;
    await this.send(to, verificationEmail(link, this.verificationTtlMs));
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
    await this.transporter.sendMail({
      from: this.from,
      to,
      subject: content.subject,
      text: content.text,
      html: content.html,
    });
    this.logger.log(`Email "${content.subject}" inviata`);
  }
}
