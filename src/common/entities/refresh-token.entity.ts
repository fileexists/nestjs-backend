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

/**
 * An issued refresh token (one per rotation). All the tokens of the same
 * session share `familyId`: if an already used one is presented again
 * (theft) the whole family is revoked. Only the SHA-256 of the jti is stored in the database.
 */
@Entity('refresh_tokens')
@Index('IDX_refresh_tokens_family', ['familyId'])
@Index('IDX_refresh_tokens_user', ['userId'])
@Index('IDX_refresh_tokens_expires_at', ['expiresAt'])
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user?: User;

  @Column({ type: 'varchar', length: 64, unique: true })
  jtiHash: string;

  @Column({ type: 'uuid' })
  familyId: string;

  /** Set on rotation: a used token cannot be used again. */
  @Column({ type: 'timestamptz', nullable: true })
  usedAt: Date | null;

  /** Set on revocation (logout, reuse detection, logout-all). */
  @Column({ type: 'timestamptz', nullable: true })
  revokedAt: Date | null;

  @Column({ type: 'timestamptz' })
  expiresAt: Date;

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;
}
