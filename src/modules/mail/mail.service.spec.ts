import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import {
  MAIL_RETRY_DELAYS_MS,
  MailService,
  isTransientMailError,
} from './mail.service';
import { humanizeTtl } from './mail.templates';

jest.mock('nodemailer');

describe('MailService', () => {
  const sendMail = jest.fn().mockResolvedValue({});
  const createTransport = nodemailer.createTransport as jest.Mock;

  function build(env: Record<string, unknown> = {}): MailService {
    const values: Record<string, unknown> = {
      SMTP_HOST: 'mailpit',
      SMTP_PORT: 1025,
      MAIL_FROM: 'Test <no-reply@test.local>',
      FRONTEND_URL: 'https://app.example.com,https://admin.example.com',
      EMAIL_VERIFICATION_TTL: '24h',
      PASSWORD_RESET_TTL: '1h',
      ...env,
    };
    return new MailService({
      get: (k: string) => values[k],
    } as unknown as ConfigService);
  }

  beforeEach(() => {
    jest.clearAllMocks();
    createTransport.mockReturnValue({ sendMail });
  });

  it('usa SMTP_HOST e SMTP_PORT per il trasporto', () => {
    build();
    expect(createTransport).toHaveBeenCalledWith(
      expect.objectContaining({ host: 'mailpit', port: 1025, secure: false }),
    );
  });

  it('autentica solo se SMTP_USER e impostato', () => {
    build();
    expect(
      ((createTransport.mock.calls as unknown[][])[0][0] as { auth?: unknown })
        .auth,
    ).toBeUndefined();
    createTransport.mockClear();
    build({ SMTP_USER: 'u', SMTP_PASS: 'p' });
    expect(
      ((createTransport.mock.calls as unknown[][])[0][0] as { auth?: unknown })
        .auth,
    ).toEqual({ user: 'u', pass: 'p' });
  });

  it('il link di verifica punta alla PRIMA origine del frontend e contiene il token', async () => {
    await build().sendVerificationEmail('user@example.com', 'tok_abc-123');

    const message = (sendMail.mock.calls as unknown[][])[0][0] as {
      to: string;
      from: string;
      subject: string;
      text: string;
      html: string;
    };
    expect(message.to).toBe('user@example.com');
    expect(message.from).toBe('Test <no-reply@test.local>');
    expect(message.text).toContain(
      'https://app.example.com/verify-email?token=tok_abc-123',
    );
    expect(message.html).toContain(
      'https://app.example.com/verify-email?token=tok_abc-123',
    );
    expect(message.text).not.toContain('admin.example.com');
  });

  it('codifica il token nell URL e scappa l HTML', async () => {
    await build().sendVerificationEmail('user@example.com', 'a b&c');
    const message = (sendMail.mock.calls as unknown[][])[0][0] as {
      text: string;
      html: string;
    };
    expect(message.text).toContain('token=a%20b%26c');
    expect(message.html).not.toContain('token=a b&c');
  });

  it("l'avviso di registrazione contiene i link di accesso e di reset verso il frontend", async () => {
    await build().sendRegistrationNotice('user@example.com');

    const message = (sendMail.mock.calls as unknown[][])[0][0] as {
      to: string;
      subject: string;
      text: string;
    };
    expect(message.to).toBe('user@example.com');
    expect(message.subject).toMatch(/registrazione/i);
    expect(message.text).toContain('https://app.example.com/login');
    expect(message.text).toContain('https://app.example.com/forgot-password');
    expect(message.text).not.toContain('token=');
  });

  it('il link di reset password punta al frontend e contiene il token (valido 1 ora)', async () => {
    await build().sendPasswordResetEmail('user@example.com', 'reset_tok-1');

    const message = (sendMail.mock.calls as unknown[][])[0][0] as {
      text: string;
      html: string;
      subject: string;
    };
    expect(message.subject).toMatch(/password/i);
    expect(message.text).toContain(
      'https://app.example.com/reset-password?token=reset_tok-1',
    );
    expect(message.html).toContain('/reset-password?token=reset_tok-1');
    expect(message.text).toMatch(/1 ora/);
  });

  it('propaga gli errori SMTP al chiamante', async () => {
    sendMail.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    await expect(
      build().sendVerificationEmail('user@example.com', 't'),
    ).rejects.toThrow('ECONNREFUSED');
  });

  describe('tentativi', () => {
    const timeout = () =>
      Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' });

    beforeEach(() => {
      jest.useFakeTimers();
      sendMail.mockReset().mockResolvedValue({});
    });
    afterEach(() => {
      jest.useRealTimers();
    });

    it('riprova dopo un errore di rete e alla fine invia', async () => {
      sendMail.mockRejectedValueOnce(timeout());
      const sending = build().sendVerificationEmail('user@example.com', 't');

      await jest.advanceTimersByTimeAsync(MAIL_RETRY_DELAYS_MS[0]);
      await sending;

      expect(sendMail).toHaveBeenCalledTimes(2);
    });

    it('rinuncia dopo 3 tentativi e propaga l ultimo errore', async () => {
      sendMail.mockRejectedValue(timeout());
      const sending = build().sendVerificationEmail('user@example.com', 't');
      const outcome = expect(sending).rejects.toThrow('timeout');

      await jest.advanceTimersByTimeAsync(
        MAIL_RETRY_DELAYS_MS.reduce((a, b) => a + b, 0),
      );
      await outcome;

      expect(sendMail).toHaveBeenCalledTimes(3);
    });

    it('non riprova un errore definitivo (rifiuto 5xx)', async () => {
      sendMail.mockRejectedValue(
        Object.assign(new Error('mailbox unavailable'), { responseCode: 550 }),
      );

      await expect(
        build().sendVerificationEmail('user@example.com', 't'),
      ).rejects.toThrow('mailbox unavailable');
      expect(sendMail).toHaveBeenCalledTimes(1);
    });
  });
});

describe('isTransientMailError', () => {
  it.each([
    [{ code: 'ETIMEDOUT' }, true],
    [{ code: 'ECONNECTION' }, true],
    [{ responseCode: 421 }, true],
    [{ responseCode: 450 }, true],
    [{ responseCode: 550 }, false],
    [{ code: 'EAUTH', responseCode: 535 }, false],
    [new Error('boh'), false],
    [null, false],
  ])('%j -> %s', (error, expected) => {
    expect(isTransientMailError(error)).toBe(expected);
  });
});

describe('humanizeTtl', () => {
  it.each([
    [60_000, '1 minuto'],
    [30 * 60_000, '30 minuti'],
    [3_600_000, '1 ora'],
    [24 * 3_600_000, '24 ore'],
    [72 * 3_600_000, '3 giorni'],
  ])('%i ms -> %s', (ms, label) => {
    expect(humanizeTtl(ms)).toBe(label);
  });
});
