import { AuthToken } from '../../src/common/entities/auth-token.entity';
import { MailService } from '../../src/modules/mail/mail.service';

/**
 * Dipendenze "nuove" che gli e2e con repository mockati devono comunque sostituire:
 * repository dei token monouso e invio email (mai SMTP vero in questi test).
 * Quando AppModule acquisisce un repository o un servizio esterno nuovo, si aggiunge QUI.
 */
export { AuthToken, MailService };

export const authTokenRepositoryMock = () => ({
  delete: jest.fn().mockResolvedValue({ affected: 0 }),
  insert: jest.fn().mockResolvedValue({}),
  findOne: jest.fn().mockResolvedValue(null),
  createQueryBuilder: jest.fn(),
});

export const mailServiceMock = () => ({
  sendVerificationEmail: jest.fn().mockResolvedValue(undefined),
});
