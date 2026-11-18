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

  /** A uniqueness violation (email or googleId already present, even from a race) becomes 409, never 500. */
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
   * Email confirmation: the account becomes verified with the password chosen by whoever
   * confirmed (the one from registration may belong to someone else). Only if it is not
   * already verified: a verification token must never change the password of an
   * active account. Returns false if the account no longer exists or was already verified.
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
   * Google has proven ownership of the email of an UNVERIFIED local account:
   * whoever created it is not necessarily the owner, so the password
   * is wiped and the sessions invalidated (tokenVersion + 1) before linking.
   * A single conditional UPDATE: if the account was verified in the meantime it does nothing
   * and returns null.
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
   * Password reset via email link: new password, email considered verified (the link
   * proves ownership of the mailbox), a Google-only account becomes "combined" and the sessions
   * are invalidated (tokenVersion + 1). A single UPDATE.
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
