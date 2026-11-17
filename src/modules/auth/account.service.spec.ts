import { BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import { AccountService, RESEND_COOLDOWN_MS } from './account.service';
import { AuthTokenService } from './auth-token.service';
import { AuthTokenType } from '../../common/entities/auth-token.entity';
import { UserService } from '../user/user.service';
import { MailService } from '../mail/mail.service';

describe('AccountService (verifica email)', () => {
  const userService = {
    getUserByEmail: jest.fn(),
    markEmailVerified: jest.fn(),
  };
  const authTokens = {
    issue: jest.fn(),
    consume: jest.fn(),
    findLatestActive: jest.fn(),
  };
  const mail = { sendVerificationEmail: jest.fn() };
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
    it('segna verificato l utente del token consumato', async () => {
      authTokens.consume.mockResolvedValue('u1');
      await service.verifyEmail('raw-token');
      expect(authTokens.consume).toHaveBeenCalledWith(
        'raw-token',
        AuthTokenType.EMAIL_VERIFICATION,
      );
      expect(userService.markEmailVerified).toHaveBeenCalledWith('u1');
    });

    it('rifiuta token non valido, scaduto o gia usato con 400', async () => {
      authTokens.consume.mockResolvedValue(null);
      await expect(service.verifyEmail('bad')).rejects.toBeInstanceOf(
        BadRequestException,
      );
      expect(userService.markEmailVerified).not.toHaveBeenCalled();
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
});
