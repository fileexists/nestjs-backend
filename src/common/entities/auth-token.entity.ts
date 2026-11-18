import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { User } from './user.entity';

export enum AuthTokenType {
  EMAIL_VERIFICATION = 'email_verification',
  PASSWORD_RESET = 'password_reset',
  /** Not a token: records that the "registration on an existing email" notice was sent, to limit how often it is sent. */
  REGISTRATION_NOTICE = 'registration_notice',
}

/**
 * Single-use token with an expiry (email verification, password reset).
 * Only the SHA-256 of the token is kept in the database: whoever reads the table
 * cannot rebuild a valid link.
 */
@Entity('auth_tokens')
@Index('IDX_auth_tokens_user_type', ['userId', 'type'])
@Index('IDX_auth_tokens_expires_at', ['expiresAt'])
export class AuthToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Column({ type: 'varchar', length: 30 })
  type: AuthTokenType;

  @Column({ type: 'varchar', length: 64, unique: true })
  tokenHash: string;

  @Column({ type: 'timestamptz' })
  expiresAt: Date;

  @Column({ type: 'timestamptz', nullable: true })
  usedAt: Date | null;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;
}
