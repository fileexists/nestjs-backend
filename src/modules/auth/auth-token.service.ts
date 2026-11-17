import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { createHash, randomBytes } from 'crypto';
import { IsNull, LessThan, Repository } from 'typeorm';
import {
  AuthToken,
  AuthTokenType,
} from '../../common/entities/auth-token.entity';

/**
 * Token monouso con scadenza (verifica email, reset password).
 * Il token in chiaro esiste solo nell'email: nel database c'e' solo lo SHA-256.
 */
@Injectable()
export class AuthTokenService {
  constructor(
    @InjectRepository(AuthToken)
    private readonly repository: Repository<AuthToken>,
  ) {}

  static hash(rawToken: string): string {
    return createHash('sha256').update(rawToken).digest('hex');
  }

  /** Crea un token nuovo; quelli non ancora usati dello stesso tipo vengono invalidati. */
  async issue(
    userId: string,
    type: AuthTokenType,
    ttlMs: number,
  ): Promise<string> {
    const rawToken = randomBytes(32).toString('base64url');
    await this.repository.delete({ userId, type, usedAt: IsNull() });
    await this.repository.insert({
      userId,
      type,
      tokenHash: AuthTokenService.hash(rawToken),
      expiresAt: new Date(Date.now() + ttlMs),
    });
    return rawToken;
  }

  /**
   * Consuma il token in modo atomico (un solo UPDATE condizionale): due richieste
   * concorrenti con lo stesso token non possono riuscire entrambe.
   * Ritorna lo userId, oppure null se il token e' sconosciuto, scaduto o gia' usato.
   */
  async consume(rawToken: string, type: AuthTokenType): Promise<string | null> {
    const result = await this.repository
      .createQueryBuilder()
      .update(AuthToken)
      .set({ usedAt: () => 'now()' })
      .where(
        `"tokenHash" = :hash AND "type" = :type AND "usedAt" IS NULL AND "expiresAt" > now()`,
        { hash: AuthTokenService.hash(rawToken), type },
      )
      .returning('"userId"')
      .execute();
    const rows = result.raw as { userId: string }[];
    return rows[0]?.userId ?? null;
  }

  /** Token piu' recente non ancora usato (serve a limitare i reinvii). */
  findLatestActive(
    userId: string,
    type: AuthTokenType,
  ): Promise<AuthToken | null> {
    return this.repository.findOne({
      where: { userId, type, usedAt: IsNull() },
      order: { createdAt: 'DESC' },
    });
  }

  /** Invalida tutti i token non usati dell'utente (opzionalmente di un solo tipo). */
  async invalidateAll(userId: string, type?: AuthTokenType): Promise<void> {
    await this.repository.delete(
      type ? { userId, type, usedAt: IsNull() } : { userId, usedAt: IsNull() },
    );
  }

  /** Pulizia periodica: elimina i token scaduti. Ritorna quanti ne ha rimossi. */
  async deleteExpired(): Promise<number> {
    const result = await this.repository.delete({
      expiresAt: LessThan(new Date()),
    });
    return result.affected ?? 0;
  }
}
