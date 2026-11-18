import { AuthToken } from '../../src/common/entities/auth-token.entity';
import { LoginAttempt } from '../../src/common/entities/login-attempt.entity';
import { RefreshToken } from '../../src/common/entities/refresh-token.entity';
import { MailService } from '../../src/modules/mail/mail.service';

/**
 * "New" dependencies that the mocked-repository e2e tests must replace anyway:
 * the repository of the single-use tokens and the email sending (never a real SMTP in these tests).
 * When AppModule gets a new repository or external service, it is added HERE.
 */
export { AuthToken, LoginAttempt, RefreshToken, MailService };

export const authTokenRepositoryMock = () => ({
  delete: jest.fn().mockResolvedValue({ affected: 0 }),
  insert: jest.fn().mockResolvedValue({}),
  findOne: jest.fn().mockResolvedValue(null),
  createQueryBuilder: jest.fn(),
});

/**
 * Refresh token repository for the mocked-repository e2e tests: every rotation
 * succeeds (simulated UPDATE ... RETURNING) and every session is active (the query of
 * `findActiveSession` returns `tokenVersion`). Real rotation, reuse, revocation and
 * immediate logout are verified against PostgreSQL in test/db/b1-refresh-rotation.e2e-spec.ts
 * and test/db/g1-session-logout.e2e-spec.ts.
 */
export const refreshTokenRepositoryMock = (
  rotatedRow: { userId: string; familyId: string } = {
    userId: 'user-local-uuid',
    familyId: 'family-e2e',
  },
  activeSession: { tokenVersion: number } | undefined = { tokenVersion: 0 },
) => {
  const queryBuilder = {
    update: jest.fn().mockReturnThis(),
    set: jest.fn().mockReturnThis(),
    where: jest.fn().mockReturnThis(),
    returning: jest.fn().mockReturnThis(),
    execute: jest.fn().mockResolvedValue({ raw: [rotatedRow] }),
    innerJoin: jest.fn().mockReturnThis(),
    select: jest.fn().mockReturnThis(),
    andWhere: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    getRawOne: jest.fn().mockResolvedValue(activeSession),
  };
  return {
    insert: jest.fn().mockResolvedValue({}),
    update: jest.fn().mockResolvedValue({ affected: 0 }),
    delete: jest.fn().mockResolvedValue({ affected: 0 }),
    findOne: jest.fn().mockResolvedValue(null),
    createQueryBuilder: jest.fn(() => queryBuilder),
  };
};

/**
 * No locked account: the transaction of `registerAttempt` always sees a "clean"
 * row. The real lock is verified on PostgreSQL in test/db/d2-login-lockout.e2e-spec.ts.
 */
export const loginAttemptRepositoryMock = () => {
  const tx = {
    query: jest
      .fn()
      .mockResolvedValue([
        { failedCount: 0, lockLevel: 0, locked: false, stale: false },
      ]),
  };
  return {
    delete: jest.fn().mockResolvedValue({ affected: 0 }),
    createQueryBuilder: jest.fn(),
    manager: {
      transaction: jest.fn((work: (t: typeof tx) => Promise<unknown>) =>
        work(tx),
      ),
    },
  };
};

export const mailServiceMock = () => ({
  sendVerificationEmail: jest.fn().mockResolvedValue(undefined),
  sendRegistrationNotice: jest.fn().mockResolvedValue(undefined),
  sendPasswordResetEmail: jest.fn().mockResolvedValue(undefined),
});
