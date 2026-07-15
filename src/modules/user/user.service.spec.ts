import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { getRepositoryToken } from '@nestjs/typeorm';
import { UserService } from './user.service';
import { User } from '../../common/entities/user.entity';
import { Permission } from '../../common/entities/permission.entity';

function buildPermission(overrides: Partial<Permission> = {}): Permission {
  const p = new Permission();
  p.id = 'perm-uuid-1';
  p.name = 'USER';
  p.description = 'Standard user';
  p.users = [];
  return Object.assign(p, overrides);
}

function buildUser(overrides: Partial<User> = {}): User {
  const u = new User();
  u.id = 'user-uuid-1';
  u.email = 'test@example.com';
  u.password = '$2b$10$hashedPassword';
  u.provider = 'local';
  u.googleId = undefined;
  u.permissions = [buildPermission()];
  u.createdAt = new Date('2024-01-01T00:00:00.000Z');
  u.updatedAt = new Date('2024-01-01T00:00:00.000Z');
  return Object.assign(u, overrides);
}

const mockUserRepository = {
  create: jest.fn(),
  save: jest.fn(),
  findOne: jest.fn(),
  find: jest.fn(),
  findAndCount: jest.fn(),
  update: jest.fn(),
  delete: jest.fn(),
  increment: jest.fn(),
};

describe('UserService', () => {
  let service: UserService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        { provide: getRepositoryToken(User), useValue: mockUserRepository },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createUser', () => {
    it('should create and persist a new user, returning the saved entity', async () => {
      const data: Partial<User> = {
        email: 'new@example.com',
        password: 'hash',
        provider: 'local',
      };
      const createdUser = buildUser({
        email: data.email,
        password: data.password,
      });

      mockUserRepository.create.mockReturnValue(createdUser);
      mockUserRepository.save.mockResolvedValue(createdUser);

      const result = await service.createUser(data);

      expect(mockUserRepository.create).toHaveBeenCalledWith(data);
      expect(mockUserRepository.save).toHaveBeenCalledWith(createdUser);
      expect(result).toEqual(createdUser);
    });

    it('should propagate a database error thrown by repository.save', async () => {
      mockUserRepository.create.mockReturnValue({});
      mockUserRepository.save.mockRejectedValue(
        new Error('DB connection lost'),
      );

      await expect(
        service.createUser({ email: 'fail@example.com' }),
      ).rejects.toThrow('DB connection lost');
    });
  });

  describe('getUserByEmail', () => {
    it('should return a user when the email exists', async () => {
      const user = buildUser();
      mockUserRepository.findOne.mockResolvedValue(user);

      const result = await service.getUserByEmail(user.email);

      expect(mockUserRepository.findOne).toHaveBeenCalledWith({
        where: { email: user.email },
        relations: ['permissions'],
      });
      expect(result).toEqual(user);
    });

    it('should return null when no user matches the email', async () => {
      mockUserRepository.findOne.mockResolvedValue(null);

      const result = await service.getUserByEmail('nobody@example.com');

      expect(result).toBeNull();
    });
  });

  describe('getUserById', () => {
    it('should return a user when the id exists', async () => {
      const user = buildUser();
      mockUserRepository.findOne.mockResolvedValue(user);

      const result = await service.getUserById(user.id);

      expect(mockUserRepository.findOne).toHaveBeenCalledWith({
        where: { id: user.id },
        relations: ['permissions'],
      });
      expect(result).toEqual(user);
    });

    it('should return null when no user matches the id', async () => {
      mockUserRepository.findOne.mockResolvedValue(null);

      const result = await service.getUserById('non-existent-uuid');

      expect(result).toBeNull();
    });
  });

  describe('getUserPermissions', () => {
    it('should return the permissions array when the user exists', async () => {
      const permission = buildPermission();
      const user = buildUser({ permissions: [permission] });
      mockUserRepository.findOne.mockResolvedValue(user);

      const result = await service.getUserPermissions(user.id);

      expect(result).toEqual([permission]);
    });

    it('should return null when the user does not exist', async () => {
      mockUserRepository.findOne.mockResolvedValue(null);

      const result = await service.getUserPermissions('unknown-uuid');

      expect(result).toBeNull();
    });

    it('should return an empty array when the user exists but has no permissions', async () => {
      const user = buildUser({ permissions: [] });
      mockUserRepository.findOne.mockResolvedValue(user);

      const result = await service.getUserPermissions(user.id);

      expect(result).toEqual([]);
    });
  });

  describe('getAllUsers', () => {
    it('should return paginated users with total count', async () => {
      const users = [
        buildUser(),
        buildUser({ id: 'user-uuid-2', email: 'other@example.com' }),
      ];
      mockUserRepository.findAndCount.mockResolvedValue([users, 2]);

      const result = await service.getAllUsers();

      expect(mockUserRepository.findAndCount).toHaveBeenCalledTimes(1);
      expect(result.data).toHaveLength(2);
      expect(result.total).toBe(2);
      expect(result.page).toBe(1);
      expect(result.limit).toBe(20);
    });

    it('should respect custom page and limit parameters', async () => {
      mockUserRepository.findAndCount.mockResolvedValue([[], 0]);

      await service.getAllUsers(2, 10);

      expect(mockUserRepository.findAndCount).toHaveBeenCalledWith(
        expect.objectContaining({ skip: 10, take: 10 }),
      );
    });

    it('should return empty data with total=0 when no users exist', async () => {
      mockUserRepository.findAndCount.mockResolvedValue([[], 0]);

      const result = await service.getAllUsers();

      expect(result.data).toEqual([]);
      expect(result.total).toBe(0);
    });
  });

  describe('updateUser', () => {
    it('should call repository.update and return the updated user entity', async () => {
      const user = buildUser();
      const updatedUser = buildUser({ provider: 'combined' });

      mockUserRepository.update.mockResolvedValue({ affected: 1 });
      mockUserRepository.findOne.mockResolvedValue(updatedUser);

      const result = await service.updateUser(user.id, {
        provider: 'combined',
      });

      expect(mockUserRepository.update).toHaveBeenCalledWith(user.id, {
        provider: 'combined',
      });
      expect(result).toEqual(updatedUser);
    });

    it('should throw NotFoundException when the user is not found after the update', async () => {
      mockUserRepository.update.mockResolvedValue({ affected: 0 });
      mockUserRepository.findOne.mockResolvedValue(null);

      await expect(
        service.updateUser('unknown-uuid', { provider: 'local' }),
      ).rejects.toThrow(NotFoundException);
      await expect(
        service.updateUser('unknown-uuid', { provider: 'local' }),
      ).rejects.toThrow('User not found');
    });
  });

  describe('deleteUser', () => {
    it('should call repository.delete when the user exists', async () => {
      const user = buildUser();
      mockUserRepository.findOne.mockResolvedValue(user);
      mockUserRepository.delete.mockResolvedValue({ affected: 1 });

      await service.deleteUser(user.id);

      expect(mockUserRepository.findOne).toHaveBeenCalledWith({
        where: { id: user.id },
      });
      expect(mockUserRepository.delete).toHaveBeenCalledWith(user.id);
    });

    it('should throw NotFoundException when the user does not exist', async () => {
      mockUserRepository.findOne.mockResolvedValue(null);

      await expect(service.deleteUser('non-existent-uuid')).rejects.toThrow(
        NotFoundException,
      );
      await expect(service.deleteUser('non-existent-uuid')).rejects.toThrow(
        'User not found',
      );
    });
  });

  describe('incrementTokenVersion', () => {
    it('should atomically increment the tokenVersion column for the given user id', async () => {
      mockUserRepository.increment.mockResolvedValue({ affected: 1 });

      await service.incrementTokenVersion('user-uuid-1');

      expect(mockUserRepository.increment).toHaveBeenCalledWith(
        { id: 'user-uuid-1' },
        'tokenVersion',
        1,
      );
    });
  });
});
