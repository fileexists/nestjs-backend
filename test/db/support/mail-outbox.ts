export type MailKind = 'verification';

export interface SentMail {
  kind: MailKind;
  to: string;
  token: string;
}

/**
 * Sostituisce MailService negli e2e: registra i messaggi invece di spedirli
 * e permette ai test di leggere i token "ricevuti via email".
 */
export class MailOutbox {
  readonly sent: SentMail[] = [];

  sendVerificationEmail(to: string, token: string): Promise<void> {
    this.sent.push({ kind: 'verification', to, token });
    return Promise.resolve();
  }

  clear(): void {
    this.sent.length = 0;
  }

  to(address: string, kind?: MailKind): SentMail[] {
    return this.sent.filter(
      (m) => m.to === address && (kind === undefined || m.kind === kind),
    );
  }

  /** Token dell'ultimo messaggio di quel tipo inviato all'indirizzo. */
  lastToken(address: string, kind: MailKind): string {
    const mail = this.to(address, kind).at(-1);
    if (!mail) throw new Error(`Nessuna email "${kind}" inviata a ${address}`);
    return mail.token;
  }
}
