import { AuthToken } from '../../src/common/entities/auth-token.entity';
import { LoginAttempt } from '../../src/common/entities/login-attempt.entity';
import { RefreshToken } from '../../src/common/entities/refresh-token.entity';
import { MailService } from '../../src/modules/mail/mail.service';

/**
 * Dipendenze "nuove" che gli e2e con repository mockati devono comunque sostituire:
 * repository dei token monouso e invio email (mai SMTP vero in questi test).
 * Quando AppModule acquisisce un repository o un servizio esterno nuovo, si aggiunge QUI.
 */
export { AuthToken, LoginAttempt, RefreshToken, MailService };

export const authTokenRepositoryMock = () => ({
  delete: jest.fn().mockResolvedValue({ affected: 0 }),
  insert: jest.fn().mockResolvedValue({}),
  findOne: jest.fn().mockResolvedValue(null),
  createQueryBuilder: jest.fn(),
});

/**
 * Repository dei refresh token per gli e2e a repository mockati: ogni rotazione
 * riesce (UPDATE ... RETURNING simulato). La rotazione vera, il riuso e la revoca
 * sono verificati contro PostgreSQL in test/db/b1-refresh-rotation.e2e-spec.ts.
 */
export const refreshTokenRepositoryMock = (
  rotatedRow: { userId: string; familyId: string } = {
    userId: 'user-local-uuid',
    familyId: 'family-e2e',
  },
) => {
  const queryBuilder = {
    update: jest.fn().mockReturnThis(),
    set: jest.fn().mockReturnThis(),
    where: jest.fn().mockReturnThis(),
    returning: jest.fn().mockReturnThis(),
    execute: jest.fn().mockResolvedValue({ raw: [rotatedRow] }),
  };
  return {
    insert: jest.fn().mockResolvedValue({}),
    update: jest.fn().mockResolvedValue({ affected: 0 }),
    delete: jest.fn().mockResolvedValue({ affected: 0 }),
    findOne: jest.fn().mockResolvedValue(null),
    createQueryBuilder: jest.fn(() => queryBuilder),
  };
};

/** Nessun account bloccato; i conteggi veri sono verificati in test/db/d2-login-lockout.e2e-spec.ts. */
export const loginAttemptRepositoryMock = () => ({
  query: jest.fn().mockResolvedValue([]),
  delete: jest.fn().mockResolvedValue({ affected: 0 }),
  createQueryBuilder: jest.fn(),
});

export const mailServiceMock = () => ({
  sendVerificationEmail: jest.fn().mockResolvedValue(undefined),
  sendRegistrationNotice: jest.fn().mockResolvedValue(undefined),
  sendPasswordResetEmail: jest.fn().mockResolvedValue(undefined),
});
