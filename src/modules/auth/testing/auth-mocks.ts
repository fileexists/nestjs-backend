import type { Provider } from '@nestjs/common';
import { AccountService } from '../account.service';
import { AuthTokenService } from '../auth-token.service';
import { RefreshTokenService } from '../refresh-token.service';
import { LoginAttemptService } from '../login-attempt.service';
import { MailService } from '../../mail/mail.service';

/**
 * Shared mocks of AuthService's collaborators for the unit tests.
 * When AuthService gets a new dependency it is added HERE, so that all
 * the specs that build the module stay aligned.
 */
export const mockAuthTokenService = {
  issue: jest.fn(),
  consume: jest.fn(),
  findLatestActive: jest.fn(),
  invalidateAll: jest.fn(),
  deleteExpired: jest.fn(),
};

export const mockRefreshTokenService = {
  create: jest.fn(),
  rotate: jest.fn(),
  findActiveSession: jest.fn(),
  revokeFamily: jest.fn(),
  revokeAllForUser: jest.fn(),
  deleteExpired: jest.fn(),
};

export const mockLoginAttemptService = {
  registerAttempt: jest.fn(),
  reset: jest.fn(),
  deleteStale: jest.fn(),
};

export const mockMailService = {
  sendVerificationEmail: jest.fn(),
  sendRegistrationNotice: jest.fn(),
  sendPasswordResetEmail: jest.fn(),
};

export const mockAccountService = {
  sendVerification: jest.fn(),
  sendRegistrationNotice: jest.fn(),
  verifyEmail: jest.fn(),
  resendVerification: jest.fn(),
  requestPasswordReset: jest.fn(),
  queueResendVerification: jest.fn(),
  queuePasswordReset: jest.fn(),
};

export function extraAuthProviders(): Provider[] {
  return [
    { provide: AuthTokenService, useValue: mockAuthTokenService },
    { provide: RefreshTokenService, useValue: mockRefreshTokenService },
    { provide: LoginAttemptService, useValue: mockLoginAttemptService },
    { provide: MailService, useValue: mockMailService },
    { provide: AccountService, useValue: mockAccountService },
  ];
}

export function resetAuthMocks(): void {
  for (const mock of [
    mockAuthTokenService,
    mockRefreshTokenService,
    mockLoginAttemptService,
    mockMailService,
    mockAccountService,
  ]) {
    Object.values(mock).forEach((fn) => fn.mockReset());
  }
}
