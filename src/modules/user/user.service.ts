import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { IsNull, Repository } from 'typeorm';
import { User } from '../../common/entities/user.entity';
import { Permission } from '../../common/entities/permission.entity';
import { isUniqueViolation } from '../../common/utils/db-errors';
import { normalizeEmail } from '../../common/utils/email';

export interface PaginatedUsers {
  data: User[];
  total: number;
  page: number;
  limit: number;
}

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  /** Una violazione di unicita' (email o googleId gia' presenti, anche per corsa) diventa 409, mai 500. */
  async createUser(data: Partial<User>): Promise<User> {
    const user = this.userRepository.create(
      data.email ? { ...data, email: normalizeEmail(data.email) } : data,
    );
    try {
      return await this.userRepository.save(user);
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new ConflictException('User already exists');
      }
      throw error;
    }
  }

  async getUserByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { email: normalizeEmail(email) },
      relations: { permissions: true },
    });
  }

  async getUserByGoogleId(googleId: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { googleId },
      relations: { permissions: true },
    });
  }

  async getUserById(id: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { id },
      relations: { permissions: true },
    });
  }

  /** Stato minimo per validare una sessione a ogni richiesta (una query per chiave primaria). */
  async getAuthState(id: string): Promise<{ tokenVersion: number } | null> {
    const user = await this.userRepository.findOne({
      where: { id },
      select: { id: true, tokenVersion: true },
    });
    return user ? { tokenVersion: user.tokenVersion } : null;
  }

  async getUserPermissions(id: string): Promise<Permission[] | null> {
    const user = await this.userRepository.findOne({
      where: { id },
      relations: { permissions: true },
    });
    return user ? user.permissions : null;
  }

  async getAllUsers(page = 1, limit = 20): Promise<PaginatedUsers> {
    const [data, total] = await this.userRepository.findAndCount({
      relations: { permissions: true },
      skip: (page - 1) * limit,
      take: limit,
      order: { createdAt: 'DESC' },
    });
    return { data, total, page, limit };
  }

  async updateUser(id: string, data: Partial<User>): Promise<User> {
    await this.userRepository.update(
      id,
      data.email ? { ...data, email: normalizeEmail(data.email) } : data,
    );
    const updated = await this.userRepository.findOne({ where: { id } });
    if (!updated) {
      throw new NotFoundException('User not found');
    }
    return updated;
  }

  async deleteUser(id: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    await this.userRepository.delete(id);
  }

  /**
   * Conferma dell'email: l'account diventa verificato con la password scelta da chi ha
   * confermato (quella della registrazione potrebbe essere di un altro). Solo se non e'
   * gia' verificato: un token di verifica non deve mai cambiare la password di un account
   * attivo. Ritorna false se l'account non esiste piu' o era gia' verificato.
   */
  async activateWithPassword(
    id: string,
    passwordHash: string,
  ): Promise<boolean> {
    const result = await this.userRepository.update(
      { id, emailVerifiedAt: IsNull() },
      { password: passwordHash, emailVerifiedAt: () => 'now()' },
    );
    return !!result.affected;
  }

  /**
   * Google ha dimostrato il possesso dell'email di un account locale NON verificato:
   * chi lo ha creato non e' necessariamente il proprietario, quindi la password
   * viene azzerata e le sessioni invalidate (tokenVersion + 1) prima del collegamento.
   * Un solo UPDATE condizionale: se nel frattempo l'account e' stato verificato non fa nulla
   * e ritorna null.
   */
  async claimUnverifiedForGoogle(
    id: string,
    googleId: string,
  ): Promise<User | null> {
    const result = await this.userRepository.update(
      { id, emailVerifiedAt: IsNull() },
      {
        password: () => 'NULL',
        emailVerifiedAt: () => 'now()',
        googleId,
        provider: 'google',
        tokenVersion: () => '"tokenVersion" + 1',
      },
    );
    if (!result.affected) return null;
    return this.getUserById(id);
  }

  /**
   * Password reimpostata via link email: nuova password, email considerata verificata (il link
   * dimostra il possesso della casella), un account solo-Google diventa "combined" e le sessioni
   * vengono invalidate (tokenVersion + 1). Un solo UPDATE.
   */
  async resetPassword(id: string, passwordHash: string): Promise<void> {
    await this.userRepository.update(id, {
      password: passwordHash,
      emailVerifiedAt: () => 'COALESCE("emailVerifiedAt", now())',
      tokenVersion: () => '"tokenVersion" + 1',
      provider: () =>
        `CASE WHEN "provider" = 'google' THEN 'combined' ELSE "provider" END`,
    });
  }

  async incrementTokenVersion(id: string): Promise<void> {
    await this.userRepository.increment({ id }, 'tokenVersion', 1);
  }
}
