import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToMany,
  JoinTable,
} from 'typeorm';
import { Exclude } from 'class-transformer';
import { Permission } from './permission.entity';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 255, unique: true })
  email: string;

  @Exclude()
  @Column({ type: 'varchar', length: 255, nullable: true })
  password?: string;

  @Exclude()
  @Column({ type: 'varchar', length: 255, nullable: true, unique: true })
  googleId?: string;

  @Column({ type: 'varchar', length: 50, nullable: true })
  provider?: string;

  @Exclude()
  @Column({ type: 'int', default: 0 })
  tokenVersion: number;

  /** Set when ownership of the email is proven (email link, password reset or Google). */
  @Column({ type: 'timestamptz', nullable: true })
  emailVerifiedAt?: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @ManyToMany(() => Permission, (permission) => permission.users)
  @JoinTable({
    name: 'user_permissions',
    joinColumn: { name: 'user_id', referencedColumnName: 'id' },
    inverseJoinColumn: { name: 'permission_id', referencedColumnName: 'id' },
  })
  permissions: Permission[];
}
