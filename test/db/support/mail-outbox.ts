export type MailKind =
  'verification' | 'registration-notice' | 'password-reset';

export interface SentMail {
  kind: MailKind;
  to: string;
  token: string;
}

/**
 * Replaces MailService in the e2e tests: it records the messages instead of sending them
 * and lets the tests read the tokens "received by email".
 */
export class MailOutbox {
  readonly sent: SentMail[] = [];

  /** Artificial delay (ms) of the password reset send: simulates a slow SMTP. */
  delayMs = 0;

  sendVerificationEmail(to: string, token: string): Promise<void> {
    this.sent.push({ kind: 'verification', to, token });
    return Promise.resolve();
  }

  /** "Someone tried to register with your address" (registration of an email that already exists). */
  sendRegistrationNotice(to: string): Promise<void> {
    this.sent.push({ kind: 'registration-notice', to, token: '' });
    return Promise.resolve();
  }

  async sendPasswordResetEmail(to: string, token: string): Promise<void> {
    if (this.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }
    this.sent.push({ kind: 'password-reset', to, token });
  }

  clear(): void {
    this.sent.length = 0;
  }

  to(address: string, kind?: MailKind): SentMail[] {
    // The system sends to the normalized address: tests can use any form.
    const normalized = address.trim().toLowerCase();
    return this.sent.filter(
      (m) => m.to === normalized && (kind === undefined || m.kind === kind),
    );
  }

  /** Token of the last message of that type sent to the address. */
  lastToken(address: string, kind: MailKind): string {
    const mail = this.to(address, kind).at(-1);
    if (!mail) throw new Error(`No "${kind}" email sent to ${address}`);
    return mail.token;
  }
}
