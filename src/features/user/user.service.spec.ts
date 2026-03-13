import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { UserService } from './user.service';
import { User } from '../../database/user.entity';
import { Permission } from '../../database/permission.entity';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

const mockUserRepository = {
  create: jest.fn(),
  save: jest.fn(),
  findOne: jest.fn(),
  find: jest.fn(),
  update: jest.fn(),
  delete: jest.fn(),
};

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('UserService', () => {
  let service: UserService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        {
          provide: getRepositoryToken(User),
          useValue: mockUserRepository,
        },
      ],
    }).compile();

    service = module.get<UserService>(UserService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // createUser
  // -------------------------------------------------------------------------

  describe('createUser', () => {
    it('should create and persist a new user, returning the saved entity', async () => {
      const data: Partial<User> = { email: 'new@example.com', password: 'hash', provider: 'local' };
      const createdUser = buildUser({ email: data.email, password: data.password });

      mockUserRepository.create.mockReturnValue(createdUser);
      mockUserRepository.save.mockResolvedValue(createdUser);

      const result = await service.createUser(data);

      expect(mockUserRepository.create).toHaveBeenCalledWith(data);
      expect(mockUserRepository.save).toHaveBeenCalledWith(createdUser);
      expect(result).toEqual(createdUser);
    });

    it('should propagate a database error thrown by repository.save', async () => {
      mockUserRepository.create.mockReturnValue({});
      mockUserRepository.save.mockRejectedValue(new Error('DB connection lost'));

      await expect(service.createUser({ email: 'fail@example.com' })).rejects.toThrow(
        'DB connection lost',
      );
    });
  });

  // -------------------------------------------------------------------------
  // getUserByEmail
  // -------------------------------------------------------------------------

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

  // -------------------------------------------------------------------------
  // getUserById
  // -------------------------------------------------------------------------

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

  // -------------------------------------------------------------------------
  // getUserPermissions
  // -------------------------------------------------------------------------

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

  // -------------------------------------------------------------------------
  // getAllUsers
  // -------------------------------------------------------------------------

  describe('getAllUsers', () => {
    it('should return an array of all users', async () => {
      const users = [buildUser(), buildUser({ id: 'user-uuid-2', email: 'other@example.com' })];
      mockUserRepository.find.mockResolvedValue(users);

      const result = await service.getAllUsers();

      expect(mockUserRepository.find).toHaveBeenCalledTimes(1);
      expect(result).toHaveLength(2);
      expect(result).toEqual(users);
    });

    it('should return an empty array when no users exist', async () => {
      mockUserRepository.find.mockResolvedValue([]);

      const result = await service.getAllUsers();

      expect(result).toEqual([]);
    });
  });

  // -------------------------------------------------------------------------
  // updateUser
  // -------------------------------------------------------------------------

  describe('updateUser', () => {
    it('should call repository.update and return the updated user entity', async () => {
      const user = buildUser();
      const updatedUser = buildUser({ provider: 'combined' });

      mockUserRepository.update.mockResolvedValue({ affected: 1 });
      mockUserRepository.findOne.mockResolvedValue(updatedUser);

      const result = await service.updateUser(user.id, { provider: 'combined' });

      expect(mockUserRepository.update).toHaveBeenCalledWith(user.id, { provider: 'combined' });
      expect(result).toEqual(updatedUser);
    });

    it('should throw an Error when the user is not found after the update', async () => {
      mockUserRepository.update.mockResolvedValue({ affected: 0 });
      mockUserRepository.findOne.mockResolvedValue(null);

      await expect(service.updateUser('unknown-uuid', { provider: 'local' })).rejects.toThrow(
        'User not found',
      );
    });
  });

  // -------------------------------------------------------------------------
  // deleteUser
  // -------------------------------------------------------------------------

  describe('deleteUser', () => {
    it('should call repository.delete with the provided user id', async () => {
      mockUserRepository.delete.mockResolvedValue({ affected: 1 });

      await service.deleteUser('user-uuid-1');

      expect(mockUserRepository.delete).toHaveBeenCalledWith('user-uuid-1');
    });

    it('should not throw even when the id does not exist (silent delete)', async () => {
      mockUserRepository.delete.mockResolvedValue({ affected: 0 });

      await expect(service.deleteUser('non-existent-uuid')).resolves.toBeUndefined();
    });
  });
});
