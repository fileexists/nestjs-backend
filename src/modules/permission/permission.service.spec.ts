import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { PermissionService } from './permission.service';
import { Permission } from '../../common/entities/permission.entity';
import {
  PermissionDTO,
  UpdatePermissionDTO,
} from '../../common/dto/permission.dto';

function buildPermission(overrides: Partial<Permission> = {}): Permission {
  const p = new Permission();
  p.id = 'perm-uuid-1';
  p.name = 'USER';
  p.description = 'Standard user permission';
  p.users = [];
  return Object.assign(p, overrides);
}

const mockPermissionRepository = {
  findOne: jest.fn(),
  find: jest.fn(),
  create: jest.fn(),
  save: jest.fn(),
  delete: jest.fn(),
};

describe('PermissionService', () => {
  let service: PermissionService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PermissionService,
        {
          provide: getRepositoryToken(Permission),
          useValue: mockPermissionRepository,
        },
      ],
    }).compile();

    service = module.get<PermissionService>(PermissionService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('findPermission', () => {
    it('cerca per filtro senza caricare gli utenti collegati', async () => {
      const permission = buildPermission();
      mockPermissionRepository.findOne.mockResolvedValue(permission);

      const result = await service.findPermission({ name: 'USER' });

      expect(mockPermissionRepository.findOne).toHaveBeenCalledWith({
        where: { name: 'USER' },
      });
      expect(result).toEqual(permission);
    });

    it('ritorna null se nessun permesso corrisponde', async () => {
      mockPermissionRepository.findOne.mockResolvedValue(null);

      await expect(
        service.findPermission({ name: 'NONEXISTENT' }),
      ).resolves.toBeNull();
    });
  });

  describe('findAll', () => {
    it('should return all permissions', async () => {
      const permissions = [
        buildPermission({ id: 'perm-1', name: 'USER' }),
        buildPermission({ id: 'perm-2', name: 'ADMIN' }),
      ];
      mockPermissionRepository.find.mockResolvedValue(permissions);

      const result = await service.findAll();

      expect(mockPermissionRepository.find).toHaveBeenCalledTimes(1);
      expect(result).toHaveLength(2);
      expect(result).toEqual(permissions);
    });

    it('should return an empty array when no permissions exist', async () => {
      mockPermissionRepository.find.mockResolvedValue([]);

      const result = await service.findAll();

      expect(result).toEqual([]);
    });
  });

  describe('create', () => {
    it('should create and persist a new permission entity', async () => {
      const dto: PermissionDTO = {
        name: 'MODERATOR',
        description: 'Can moderate content',
      };
      const created = buildPermission({
        name: 'MODERATOR',
        description: dto.description,
      });

      mockPermissionRepository.create.mockReturnValue(created);
      mockPermissionRepository.save.mockResolvedValue(created);

      const result = await service.create(dto);

      expect(mockPermissionRepository.create).toHaveBeenCalledWith(dto);
      expect(mockPermissionRepository.save).toHaveBeenCalledWith(created);
      expect(result).toEqual(created);
    });

    it('should propagate a duplicate-entry database error from repository.save', async () => {
      const dto: PermissionDTO = {
        name: 'USER',
        description: 'Standard user permission',
      };
      const dbError = Object.assign(new Error('Duplicate entry'), {
        code: '23505',
      });

      mockPermissionRepository.create.mockReturnValue({});
      mockPermissionRepository.save.mockRejectedValue(dbError);

      await expect(service.create(dto)).rejects.toThrow('Duplicate entry');
    });
  });

  describe('update', () => {
    it('should update an existing permission and return the updated entity', async () => {
      const original = buildPermission();
      const dto: UpdatePermissionDTO = { description: 'Updated description' };
      const updated = buildPermission({ description: dto.description });

      mockPermissionRepository.findOne.mockResolvedValue(original);
      mockPermissionRepository.save.mockResolvedValue(updated);

      const result = await service.update(original.id, dto);

      expect(mockPermissionRepository.findOne).toHaveBeenCalledWith({
        where: { id: original.id },
      });
      expect(mockPermissionRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({ description: dto.description }),
      );
      expect(result).toEqual(updated);
    });

    it('should update the name field when provided', async () => {
      const original = buildPermission();
      const dto: UpdatePermissionDTO = { name: 'SUPERUSER' };

      mockPermissionRepository.findOne.mockResolvedValue(original);
      mockPermissionRepository.save.mockImplementation((p: Permission) =>
        Promise.resolve(p),
      );

      const result = await service.update(original.id, dto);

      expect(result.name).toBe('SUPERUSER');
    });

    it('should throw NotFoundException when the permission id does not exist', async () => {
      mockPermissionRepository.findOne.mockResolvedValue(null);

      await expect(
        service.update('non-existent-id', { name: 'X' }),
      ).rejects.toThrow(NotFoundException);
      await expect(
        service.update('non-existent-id', { name: 'X' }),
      ).rejects.toThrow('Permission not found');
    });
  });

  describe('remove', () => {
    it('should call repository.delete with the permission id', async () => {
      const permission = buildPermission();
      mockPermissionRepository.findOne.mockResolvedValue(permission);
      mockPermissionRepository.delete.mockResolvedValue({ affected: 1 });

      await service.remove('perm-uuid-1');

      expect(mockPermissionRepository.delete).toHaveBeenCalledWith(
        'perm-uuid-1',
      );
    });

    it('should throw NotFoundException when the id does not exist', async () => {
      mockPermissionRepository.findOne.mockResolvedValue(null);

      await expect(service.remove('non-existent-id')).rejects.toThrow(
        NotFoundException,
      );
      await expect(service.remove('non-existent-id')).rejects.toThrow(
        'Permission not found',
      );
    });
  });

  describe('permessi indispensabili (D5)', () => {
    beforeEach(() => {
      mockPermissionRepository.create.mockImplementation((d: object) => d);
      mockPermissionRepository.save.mockImplementation((d: object) =>
        Promise.resolve(d),
      );
    });

    describe('ensureDefaults / onApplicationBootstrap', () => {
      it('crea il permesso USER se manca', async () => {
        mockPermissionRepository.findOne.mockResolvedValue(null);

        await service.ensureDefaults();

        expect(mockPermissionRepository.save).toHaveBeenCalledWith({
          name: 'USER',
          description: 'Basic user access',
        });
      });

      it('e idempotente: se esiste non scrive nulla (descrizione modificata inclusa)', async () => {
        mockPermissionRepository.findOne.mockResolvedValue(buildPermission());

        await service.ensureDefaults();
        await service.ensureDefaults();

        expect(mockPermissionRepository.save).not.toHaveBeenCalled();
      });

      it("con piu istanze in avvio: l'unicita violata da chi arriva secondo viene ignorata", async () => {
        mockPermissionRepository.findOne.mockResolvedValue(null);
        mockPermissionRepository.save.mockRejectedValue({ code: '23505' });

        await expect(service.ensureDefaults()).resolves.toBeUndefined();
      });

      it("un errore diverso (database giu) fa fallire l'avvio invece di essere nascosto", async () => {
        mockPermissionRepository.findOne.mockResolvedValue(null);
        mockPermissionRepository.save.mockRejectedValue(
          new Error('connection refused'),
        );

        await expect(service.ensureDefaults()).rejects.toThrow(
          'connection refused',
        );
      });

      it("viene eseguito all'avvio dell'applicazione", async () => {
        mockPermissionRepository.findOne.mockResolvedValue(null);

        await service.onApplicationBootstrap();

        expect(mockPermissionRepository.save).toHaveBeenCalledTimes(1);
      });
    });

    describe('getRequired', () => {
      it('ritorna il permesso senza caricare la relazione users (non scansiona tutti gli utenti)', async () => {
        const permission = buildPermission();
        mockPermissionRepository.findOne.mockResolvedValue(permission);

        await expect(service.getRequired('USER')).resolves.toBe(permission);

        expect(mockPermissionRepository.findOne).toHaveBeenCalledWith({
          where: { name: 'USER' },
        });
      });

      it('se manca risponde 503: mai un utente senza permessi in silenzio', async () => {
        mockPermissionRepository.findOne.mockResolvedValue(null);

        await expect(service.getRequired('USER')).rejects.toBeInstanceOf(
          ServiceUnavailableException,
        );
      });
    });
  });
});
