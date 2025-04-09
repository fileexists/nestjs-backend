import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../database/user.entity';
import { Permission } from '../../database/permission.entity';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async createUser(data: Partial<User>): Promise<User> {
    const user = this.userRepository.create(data);
    return await this.userRepository.save(user);
  }

  async getUserByEmail(email: string): Promise<User | null> {
    return await this.userRepository.findOne({ where: { email }, relations: ['permissions'] });
  }

  async getUserById(id: string): Promise<User | null> {
    return await this.userRepository.findOne({ where: { id }, relations: ['permissions']  });
  }

  async getUserPermissions(id: string): Promise<Permission[] | null> {
    const user = await this.userRepository.findOne({ where: { id }, relations: ['permissions'] });
    return user ? user.permissions : null;
  }

  async getAllUsers(): Promise<User[]> {
    return await this.userRepository.find();
  }

  async updateUser(id: string, data: Partial<User>): Promise<User> {
    await this.userRepository.update(id, data);
    const updatedUser = await this.userRepository.findOne({ where: { id } });
    if (!updatedUser) {
      throw new Error('User not found');
    }
    return updatedUser;
  }

  async deleteUser(id: string): Promise<void> {
    await this.userRepository.delete(id);
  }
}
