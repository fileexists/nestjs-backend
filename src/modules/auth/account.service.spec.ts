import { BadRequestException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import {
  AccountService,
  NOTICE_COOLDOWN_MS,
  RESEND_COOLDOWN_MS,
  SHUTDOWN_DRAIN_TIMEOUT_MS,
} from './account.service';
import { AuthTokenService } from './auth-token.service';
import { AuthTokenType } from '../../common/entities/auth-token.entity';
import { UserService } from '../user/user.service';
import { MailService } from '../mail/mail.service';

describe('AccountService (email verification)', () => {
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
    it('issues a verification token with the configured TTL and sends it by email', async () => {
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

    it('does not fail if SMTP is down: the error is only logged', async () => {
      mail.sendVerificationEmail.mockRejectedValue(new Error('smtp down'));
      await expect(
        service.sendVerification({ id: 'u1', email: 'a@example.com' }),
      ).resolves.toBeUndefined();
    });

    it('does not wait for the send (the HTTP response must not depend on SMTP)', async () => {
      mail.sendVerificationEmail.mockReturnValue(new Promise(() => undefined));
      await expect(
        service.sendVerification({ id: 'u1', email: 'a@example.com' }),
      ).resolves.toBeUndefined();
    });
  });

  describe('verifyEmail', () => {
    it('activates the user of the consumed token with the chosen password (already hashed)', async () => {
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

    it('rejects an invalid, expired or already used token with 400', async () => {
      authTokens.consume.mockResolvedValue(null);
      await expect(service.verifyEmail('bad', 'h')).rejects.toBeInstanceOf(
        BadRequestException,
      );
      expect(userService.activateWithPassword).not.toHaveBeenCalled();
    });

    it('account already verified (or gone): 400, the password does not change and the error is the invalid-token one', async () => {
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

    it('resends to an unverified account', async () => {
      userService.getUserByEmail.mockResolvedValue(unverified);
      authTokens.findLatestActive.mockResolvedValue(null);
      await service.resendVerification('a@example.com');
      expect(mail.sendVerificationEmail).toHaveBeenCalledWith(
        'a@example.com',
        'raw-token',
      );
    });

    it.each([
      ['nonexistent user', null],
      [
        'account already verified',
        { ...unverified, emailVerifiedAt: new Date() },
      ],
      [
        'account without a password (Google)',
        { ...unverified, password: undefined },
      ],
    ])('sends nothing and does not throw for: %s', async (_label, user) => {
      userService.getUserByEmail.mockResolvedValue(user);
      await expect(
        service.resendVerification('a@example.com'),
      ).resolves.toBeUndefined();
      expect(mail.sendVerificationEmail).not.toHaveBeenCalled();
    });

    it('respects the wait period between two sends', async () => {
      userService.getUserByEmail.mockResolvedValue(unverified);
      authTokens.findLatestActive.mockResolvedValue({
        createdAt: new Date(Date.now() - RESEND_COOLDOWN_MS / 2),
      });
      await service.resendVerification('a@example.com');
      expect(mail.sendVerificationEmail).not.toHaveBeenCalled();
    });

    it('resends after the wait period', async () => {
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

    it('notifies the owner and records the send (to limit its frequency)', async () => {
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

    it('does not send a second notice within the wait period (no flooding of the mailbox)', async () => {
      authTokens.findLatestActive.mockResolvedValue({
        createdAt: new Date(Date.now() - NOTICE_COOLDOWN_MS / 2),
      });

      await service.sendRegistrationNotice(user);

      expect(mail.sendRegistrationNotice).not.toHaveBeenCalled();
      expect(authTokens.issue).not.toHaveBeenCalled();
    });

    it('after the wait period notifies again', async () => {
      authTokens.findLatestActive.mockResolvedValue({
        createdAt: new Date(Date.now() - NOTICE_COOLDOWN_MS - 1000),
      });

      await service.sendRegistrationNotice(user);

      expect(mail.sendRegistrationNotice).toHaveBeenCalled();
    });

    it('an SMTP error does not make the registration fail', async () => {
      authTokens.findLatestActive.mockResolvedValue(null);
      mail.sendRegistrationNotice.mockRejectedValue(new Error('smtp down'));

      await expect(
        service.sendRegistrationNotice(user),
      ).resolves.toBeUndefined();
    });
  });

  describe('requestPasswordReset (E)', () => {
    const user = { id: 'u1', email: 'a@example.com' };

    it('for an existing account issues a reset token with the configured TTL and sends it', async () => {
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

    it('for a nonexistent address does nothing and does not throw (no clue given away)', async () => {
      userService.getUserByEmail.mockResolvedValue(null);

      await expect(
        service.requestPasswordReset('ghost@example.com'),
      ).resolves.toBeUndefined();
      expect(authTokens.issue).not.toHaveBeenCalled();
      expect(mail.sendPasswordResetEmail).not.toHaveBeenCalled();
    });

    it('also applies to unverified or Google-only accounts', async () => {
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

    it('respects the wait period between two requests', async () => {
      userService.getUserByEmail.mockResolvedValue(user);
      authTokens.findLatestActive.mockResolvedValue({
        createdAt: new Date(Date.now() - RESEND_COOLDOWN_MS / 2),
      });

      await service.requestPasswordReset('a@example.com');

      expect(mail.sendPasswordResetEmail).not.toHaveBeenCalled();
    });
  });

  describe('background jobs (uniform responses)', () => {
    it('runInBackground does not wait for the job, does not propagate errors, and drain waits for them', async () => {
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

    it('drain also waits for jobs queued by other jobs (e.g. sending an email inside the request)', async () => {
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

    it('queuePasswordReset and queueResendVerification return immediately and do the work afterwards', async () => {
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

    it('an error in the background job never fails the request', async () => {
      userService.getUserByEmail.mockRejectedValue(new Error('db down'));
      expect(() => service.queuePasswordReset('a@example.com')).not.toThrow();
      await expect(service.drain()).resolves.toBeUndefined();
    });
  });

  describe('shutdown', () => {
    const queueSlowJob = () => {
      let finish!: () => void;
      userService.getUserByEmail.mockImplementation(
        () =>
          new Promise((resolve) => {
            finish = () => resolve(null);
          }),
      );
      service.queuePasswordReset('a@example.com');
      return () => finish();
    };

    it('is a Nest shutdown hook', () => {
      expect(typeof service.onApplicationShutdown).toBe('function');
    });

    it('waits for the emails already queued before the process exits', async () => {
      const release = queueSlowJob();
      let done = false;
      const shutdown = service.onApplicationShutdown().then(() => {
        done = true;
      });

      await new Promise((resolve) => setImmediate(resolve));
      await new Promise((resolve) => setImmediate(resolve));
      expect(done).toBe(false);

      release();
      await shutdown;
      expect(done).toBe(true);
    });

    it('hands the wait to drain() with a time limit', async () => {
      const drain = jest.spyOn(service, 'drain').mockResolvedValue();

      await service.onApplicationShutdown();

      expect(drain).toHaveBeenCalledWith(SHUTDOWN_DRAIN_TIMEOUT_MS);
      expect(SHUTDOWN_DRAIN_TIMEOUT_MS).toBeGreaterThan(0);
    });

    it('drain(timeout) gives up on a job that never ends and says how many were left', async () => {
      const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation();
      queueSlowJob();

      await expect(service.drain(30)).resolves.toBeUndefined();

      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn.mock.calls[0][0]).toMatch(/1 background operations/);
      warn.mockRestore();
    });

    it('drain(timeout) is quiet when everything finishes in time', async () => {
      const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation();
      userService.getUserByEmail.mockResolvedValue(null);
      service.queuePasswordReset('a@example.com');

      await service.drain(1000);

      expect(warn).not.toHaveBeenCalled();
      warn.mockRestore();
    });

    it('without a timeout drain keeps waiting as before', async () => {
      const release = queueSlowJob();
      let done = false;
      const waiting = service.drain().then(() => {
        done = true;
      });

      await new Promise((resolve) => setTimeout(resolve, 40));
      expect(done).toBe(false);

      release();
      await waiting;
      expect(done).toBe(true);
    });
  });
});
