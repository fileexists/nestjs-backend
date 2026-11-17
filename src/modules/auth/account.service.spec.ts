import { BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import {
  AccountService,
  NOTICE_COOLDOWN_MS,
  RESEND_COOLDOWN_MS,
} from './account.service';
import { AuthTokenService } from './auth-token.service';
import { AuthTokenType } from '../../common/entities/auth-token.entity';
import { UserService } from '../user/user.service';
import { MailService } from '../mail/mail.service';

describe('AccountService (verifica email)', () => {
  const userService = {
    getUserByEmail: jest.fn(),
    activateWithPassword: jest.fn(),
  };
  const authTokens = {
    issue: jest.fn(),
    consume: jest.fn(),
    findLatestActive: jest.fn(),
  };
  const mail = {
    sendVerificationEmail: jest.fn(),
    sendRegistrationNotice: jest.fn(),
    sendPasswordResetEmail: jest.fn(),
  };
  const config = {
    get: jest.fn((key: string) =>
      key === 'EMAIL_VERIFICATION_TTL' ? '2h' : undefined,
    ),
  };
  let service: AccountService;

  beforeEach(async () => {
    jest.resetAllMocks();
    config.get.mockImplementation((key: string) =>
      key === 'EMAIL_VERIFICATION_TTL' ? '2h' : undefined,
    );
    mail.sendVerificationEmail.mockResolvedValue(undefined);
    mail.sendRegistrationNotice.mockResolvedValue(undefined);
    mail.sendPasswordResetEmail.mockResolvedValue(undefined);
    authTokens.issue.mockResolvedValue('raw-token');
    const module = await Test.createTestingModule({
      providers: [
        AccountService,
        { provide: UserService, useValue: userService },
        { provide: AuthTokenService, useValue: authTokens },
        { provide: MailService, useValue: mail },
        { provide: ConfigService, useValue: config },
      ],
    }).compile();
    service = module.get(AccountService);
  });

  describe('sendVerification', () => {
    it('emette un token di verifica col TTL configurato e lo invia per email', async () => {
      await service.sendVerification({ id: 'u1', email: 'a@example.com' });

      expect(authTokens.issue).toHaveBeenCalledWith(
        'u1',
        AuthTokenType.EMAIL_VERIFICATION,
        2 * 3_600_000,
      );
      expect(mail.sendVerificationEmail).toHaveBeenCalledWith(
        'a@example.com',
        'raw-token',
      );
    });

    it("non fallisce se l'SMTP e' giu: l'errore viene solo loggato", async () => {
      mail.sendVerificationEmail.mockRejectedValue(new Error('smtp down'));
      await expect(
        service.sendVerification({ id: 'u1', email: 'a@example.com' }),
      ).resolves.toBeUndefined();
    });

    it("non attende l'invio (la risposta HTTP non deve dipendere dall'SMTP)", async () => {
      mail.sendVerificationEmail.mockReturnValue(new Promise(() => undefined));
      await expect(
        service.sendVerification({ id: 'u1', email: 'a@example.com' }),
      ).resolves.toBeUndefined();
    });
  });

  describe('verifyEmail', () => {
    it("attiva l'utente del token consumato con la password scelta (gia hashata)", async () => {
      authTokens.consume.mockResolvedValue('u1');
      userService.activateWithPassword.mockResolvedValue(true);

      await service.verifyEmail('raw-token', 'new-hash');

      expect(authTokens.consume).toHaveBeenCalledWith(
        'raw-token',
        AuthTokenType.EMAIL_VERIFICATION,
      );
      expect(userService.activateWithPassword).toHaveBeenCalledWith(
        'u1',
        'new-hash',
      );
    });

    it('rifiuta token non valido, scaduto o gia usato con 400', async () => {
      authTokens.consume.mockResolvedValue(null);
      await expect(service.verifyEmail('bad', 'h')).rejects.toBeInstanceOf(
        BadRequestException,
      );
      expect(userService.activateWithPassword).not.toHaveBeenCalled();
    });

    it("account gia verificato (o sparito): 400, la password non cambia e l'errore e quello del token non valido", async () => {
      authTokens.consume.mockResolvedValue('u1');
      userService.activateWithPassword.mockResolvedValue(false);

      await expect(service.verifyEmail('old', 'h')).rejects.toThrow(
        'Invalid or expired token',
      );
    });
  });

  describe('resendVerification', () => {
    const unverified = {
      id: 'u1',
      email: 'a@example.com',
      password: 'hash',
      emailVerifiedAt: undefined,
    };

    it('reinvia a un account non verificato', async () => {
      userService.getUserByEmail.mockResolvedValue(unverified);
      authTokens.findLatestActive.mockResolvedValue(null);
      await service.resendVerification('a@example.com');
      expect(mail.sendVerificationEmail).toHaveBeenCalledWith(
        'a@example.com',
        'raw-token',
      );
    });

    it.each([
      ['utente inesistente', null],
      [
        'account gia verificato',
        { ...unverified, emailVerifiedAt: new Date() },
      ],
      [
        'account senza password (Google)',
        { ...unverified, password: undefined },
      ],
    ])('non invia nulla e non lancia per: %s', async (_label, user) => {
      userService.getUserByEmail.mockResolvedValue(user);
      await expect(
        service.resendVerification('a@example.com'),
      ).resolves.toBeUndefined();
      expect(mail.sendVerificationEmail).not.toHaveBeenCalled();
    });

    it('rispetta il periodo di attesa tra due invii', async () => {
      userService.getUserByEmail.mockResolvedValue(unverified);
      authTokens.findLatestActive.mockResolvedValue({
        createdAt: new Date(Date.now() - RESEND_COOLDOWN_MS / 2),
      });
      await service.resendVerification('a@example.com');
      expect(mail.sendVerificationEmail).not.toHaveBeenCalled();
    });

    it('reinvia dopo il periodo di attesa', async () => {
      userService.getUserByEmail.mockResolvedValue(unverified);
      authTokens.findLatestActive.mockResolvedValue({
        createdAt: new Date(Date.now() - RESEND_COOLDOWN_MS - 1000),
      });
      await service.resendVerification('a@example.com');
      expect(mail.sendVerificationEmail).toHaveBeenCalled();
    });
  });

  describe('sendRegistrationNotice (D1)', () => {
    const user = { id: 'u1', email: 'a@example.com' };

    it("avvisa il proprietario e registra l'invio (per limitarne la frequenza)", async () => {
      authTokens.findLatestActive.mockResolvedValue(null);

      await service.sendRegistrationNotice(user);

      expect(authTokens.issue).toHaveBeenCalledWith(
        'u1',
        AuthTokenType.REGISTRATION_NOTICE,
        NOTICE_COOLDOWN_MS,
      );
      expect(mail.sendRegistrationNotice).toHaveBeenCalledWith('a@example.com');
      expect(mail.sendVerificationEmail).not.toHaveBeenCalled();
    });

    it('non invia un secondo avviso entro il periodo di attesa (niente inondazione della casella)', async () => {
      authTokens.findLatestActive.mockResolvedValue({
        createdAt: new Date(Date.now() - NOTICE_COOLDOWN_MS / 2),
      });

      await service.sendRegistrationNotice(user);

      expect(mail.sendRegistrationNotice).not.toHaveBeenCalled();
      expect(authTokens.issue).not.toHaveBeenCalled();
    });

    it('dopo il periodo di attesa avvisa di nuovo', async () => {
      authTokens.findLatestActive.mockResolvedValue({
        createdAt: new Date(Date.now() - NOTICE_COOLDOWN_MS - 1000),
      });

      await service.sendRegistrationNotice(user);

      expect(mail.sendRegistrationNotice).toHaveBeenCalled();
    });

    it('un errore SMTP non fa fallire la registrazione', async () => {
      authTokens.findLatestActive.mockResolvedValue(null);
      mail.sendRegistrationNotice.mockRejectedValue(new Error('smtp down'));

      await expect(
        service.sendRegistrationNotice(user),
      ).resolves.toBeUndefined();
    });
  });

  describe('requestPasswordReset (E)', () => {
    const user = { id: 'u1', email: 'a@example.com' };

    it('per un account esistente emette un token di reset col TTL configurato e lo invia', async () => {
      userService.getUserByEmail.mockResolvedValue(user);
      authTokens.findLatestActive.mockResolvedValue(null);

      await service.requestPasswordReset('a@example.com');
      await service.drain();

      expect(authTokens.issue).toHaveBeenCalledWith(
        'u1',
        AuthTokenType.PASSWORD_RESET,
        expect.any(Number),
      );
      expect(mail.sendPasswordResetEmail).toHaveBeenCalledWith(
        'a@example.com',
        'raw-token',
      );
    });

    it('per un indirizzo inesistente non fa nulla e non lancia (nessun indizio)', async () => {
      userService.getUserByEmail.mockResolvedValue(null);

      await expect(
        service.requestPasswordReset('ghost@example.com'),
      ).resolves.toBeUndefined();
      expect(authTokens.issue).not.toHaveBeenCalled();
      expect(mail.sendPasswordResetEmail).not.toHaveBeenCalled();
    });

    it('vale anche per account non verificati o solo-Google', async () => {
      for (const account of [
        { ...user, emailVerifiedAt: undefined, password: 'hash' },
        { ...user, emailVerifiedAt: new Date(), password: undefined },
      ]) {
        userService.getUserByEmail.mockResolvedValue(account);
        authTokens.findLatestActive.mockResolvedValue(null);
        mail.sendPasswordResetEmail.mockClear();

        await service.requestPasswordReset('a@example.com');
        await service.drain();

        expect(mail.sendPasswordResetEmail).toHaveBeenCalledTimes(1);
      }
    });

    it('rispetta il periodo di attesa tra due richieste', async () => {
      userService.getUserByEmail.mockResolvedValue(user);
      authTokens.findLatestActive.mockResolvedValue({
        createdAt: new Date(Date.now() - RESEND_COOLDOWN_MS / 2),
      });

      await service.requestPasswordReset('a@example.com');

      expect(mail.sendPasswordResetEmail).not.toHaveBeenCalled();
    });
  });

  describe('lavori in background (risposte uniformi)', () => {
    it('runInBackground non aspetta il lavoro, non propaga gli errori e drain li attende', async () => {
      let finished = false;
      service.runInBackground(async () => {
        await new Promise((resolve) => setTimeout(resolve, 30));
        finished = true;
      });
      service.runInBackground(() => Promise.reject(new Error('boom')));

      expect(finished).toBe(false);
      await expect(service.drain()).resolves.toBeUndefined();
      expect(finished).toBe(true);
    });

    it('drain attende anche i lavori accodati da altri lavori (es. invio email dentro la richiesta)', async () => {
      const order: string[] = [];
      service.runInBackground(async () => {
        await Promise.resolve();
        service.runInBackground(async () => {
          await new Promise((resolve) => setTimeout(resolve, 20));
          order.push('inner');
        });
        order.push('outer');
      });

      await service.drain();

      expect(order).toEqual(['outer', 'inner']);
    });

    it('queuePasswordReset e queueResendVerification ritornano subito e fanno il lavoro dopo', async () => {
      userService.getUserByEmail.mockResolvedValue({
        id: 'u1',
        email: 'a@example.com',
        password: 'h',
      });
      authTokens.findLatestActive.mockResolvedValue(null);

      const result = service.queuePasswordReset('a@example.com');
      expect(result).toBeUndefined();
      expect(mail.sendPasswordResetEmail).not.toHaveBeenCalled();

      await service.drain();
      expect(mail.sendPasswordResetEmail).toHaveBeenCalledTimes(1);

      service.queueResendVerification('a@example.com');
      await service.drain();
      expect(mail.sendVerificationEmail).toHaveBeenCalledTimes(1);
    });

    it('un errore nel lavoro in background non fa mai fallire la richiesta', async () => {
      userService.getUserByEmail.mockRejectedValue(new Error('db down'));
      expect(() => service.queuePasswordReset('a@example.com')).not.toThrow();
      await expect(service.drain()).resolves.toBeUndefined();
    });
  });
});
