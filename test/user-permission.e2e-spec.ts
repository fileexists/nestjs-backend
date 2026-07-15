/**
 * user-permission.e2e-spec.ts
 *
 * End-to-end tests for the User and Permission HTTP layers.
 *
 * Strategy
 * --------
 * • AppModule is imported so the full NestJS DI graph is wired up.
 * • TypeORM's DataSource is overridden so NO real PostgreSQL connection is made.
 * • The User and Permission repositories are replaced with in-memory mocks.
 * • All three APP_GUARD providers (AuthGuard, PermissionsGuard, ThrottlerGuard)
 *   are overridden individually by class so NestJS replaces every registration.
 * • The AuthGuard stub decodes the access_token cookie (using JwtService.decode
 *   — no verification needed in tests) and populates req.user.
 *
 * Run with:  yarn test:e2e
 */

import { Test, TestingModule } from '@nestjs/testing';
import {
  INestApplication,
  ValidationPipe,
  ExecutionContext,
  CanActivate,
} from '@nestjs/common';
import * as request from 'supertest';
import * as cookieParser from 'cookie-parser';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { DataSource } from 'typeorm';

import { AppModule } from '../src/app.module';
import { User } from '../src/common/entities/user.entity';
import { Permission } from '../src/common/entities/permission.entity';
import { AuthGuard } from '../src/common/guards/auth.guard';
import { PermissionsGuard } from '../src/common/guards/permissions.guard';
import { ThrottlerGuard } from '@nestjs/throttler';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const USER_PERMISSION: Permission = {
  id: '11111111-1111-4111-a111-111111111111',
  name: 'USER',
  description: 'Default user permission',
  users: [],
};

const ADMIN_PERMISSION: Permission = {
  id: '22222222-2222-4222-b222-222222222222',
  name: 'ADMIN',
  description: 'Administrator permission',
  users: [],
};

const NON_EXISTENT_UUID = '99999999-9999-4999-9999-999999999999';

const REGULAR_USER: User = {
  id: 'regular-user-uuid',
  email: 'user@example.com',
  password: 'hashed',
  provider: 'local',
  googleId: undefined,
  tokenVersion: 0,
  permissions: [USER_PERMISSION],
  createdAt: new Date('2024-01-01T00:00:00.000Z'),
  updatedAt: new Date('2024-01-01T00:00:00.000Z'),
};

const ADMIN_USER: User = {
  id: 'admin-user-uuid',
  email: 'admin@example.com',
  password: 'hashed',
  provider: 'local',
  googleId: undefined,
  tokenVersion: 0,
  permissions: [ADMIN_PERMISSION],
  createdAt: new Date('2024-01-01T00:00:00.000Z'),
  updatedAt: new Date('2024-01-01T00:00:00.000Z'),
};

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

const userDb: Map<string, User> = new Map();
const permDb: Map<string, Permission> = new Map();

function resetDbs(): void {
  userDb.clear();
  permDb.clear();
  userDb.set(REGULAR_USER.id, { ...REGULAR_USER });
  userDb.set(ADMIN_USER.id, { ...ADMIN_USER });
  permDb.set(USER_PERMISSION.id, { ...USER_PERMISSION });
  permDb.set(ADMIN_PERMISSION.id, { ...ADMIN_PERMISSION });
}

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

const mockUserRepository = {
  findOne: jest.fn(),
  find: jest.fn(),
  create: jest.fn((data: Partial<User>) => ({ ...data }) as User),
  save: jest.fn(),
  update: jest.fn(),
  delete: jest.fn((id: string) => {
    userDb.delete(id);
    return Promise.resolve({ affected: 1 });
  }),
};

const mockPermissionRepository = {
  findOne: jest.fn(),
  find: jest.fn(),
  create: jest.fn((data: Partial<Permission>) => ({ ...data }) as Permission),
  save: jest.fn(),
  update: jest.fn(() => Promise.resolve({ affected: 1 })),
  delete: jest.fn((id: string) => {
    permDb.delete(id);
    return Promise.resolve({ affected: 1 });
  }),
};

// ---------------------------------------------------------------------------
// Token helpers
// ---------------------------------------------------------------------------

function buildAccessToken(jwtService: JwtService, user: User): string {
  return jwtService.sign(
    { id: user.id, email: user.email, permissions: user.permissions },
    { secret: process.env.JWT_SECRET ?? 'your_jwt_secret', expiresIn: '15m' },
  );
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

describe('User & Permission Controllers (e2e)', () => {
  let app: INestApplication;
  let jwtService: JwtService;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(DataSource)
      .useValue({
        initialize: jest.fn().mockResolvedValue(undefined),
        destroy: jest.fn().mockResolvedValue(undefined),
      })
      .overrideProvider(getRepositoryToken(User))
      .useValue(mockUserRepository)
      .overrideProvider(getRepositoryToken(Permission))
      .useValue(mockPermissionRepository)
      .overrideProvider(ThrottlerGuard)
      .useValue({ canActivate: () => Promise.resolve(true) } as CanActivate)
      .overrideProvider(PermissionsGuard)
      .useValue({ canActivate: () => Promise.resolve(true) } as CanActivate)
      .compile();

    jwtService = moduleFixture.get<JwtService>(JwtService);

    const authGuardRef = moduleFixture.get<AuthGuard>(AuthGuard);
    jest
      .spyOn(authGuardRef, 'canActivate')
      .mockImplementation(async (ctx: ExecutionContext) => {
        const req = ctx.switchToHttp().getRequest();
        const token: string | undefined = req.cookies?.access_token;
        if (token) {
          try {
            req.user = jwtService.decode(token);
          } catch {
            // leave req.user undefined
          }
        }
        return true;
      });

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api', { exclude: ['health'] });
    app.use(cookieParser());
    app.useGlobalPipes(
      new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }),
    );
    await app.init();
  });

  beforeEach(() => {
    resetDbs();
    jest.clearAllMocks();

    mockUserRepository.findOne.mockImplementation(
      ({ where }: { where: Partial<User> }) => {
        if (where.id) return Promise.resolve(userDb.get(where.id) ?? null);
        if (where.email) {
          return Promise.resolve(
            [...userDb.values()].find((u) => u.email === where.email) ?? null,
          );
        }
        return Promise.resolve(null);
      },
    );
    mockUserRepository.find.mockResolvedValue([...userDb.values()]);
    mockUserRepository.create.mockImplementation(
      (data: Partial<User>) => ({ ...data }) as User,
    );
    mockUserRepository.save.mockImplementation((u: User) => {
      const saved: User = {
        id: u.id ?? `gen-uuid-${Date.now()}`,
        email: u.email,
        password: u.password,
        googleId: u.googleId,
        provider: u.provider,
        tokenVersion: u.tokenVersion ?? 0,
        permissions: u.permissions ?? [],
        createdAt: u.createdAt ?? new Date(),
        updatedAt: new Date(),
      };
      userDb.set(saved.id, saved);
      return Promise.resolve(saved);
    });
    mockUserRepository.update.mockImplementation(
      (id: string, data: Partial<User>) => {
        const ex = userDb.get(id);
        if (ex) {
          Object.assign(ex, data);
          userDb.set(id, ex);
        }
        return Promise.resolve({ affected: ex ? 1 : 0 });
      },
    );

    mockPermissionRepository.findOne.mockImplementation(
      (query: { where: Partial<Permission> }) => {
        if (query.where.id)
          return Promise.resolve(permDb.get(query.where.id) ?? null);
        if (query.where.name) {
          return Promise.resolve(
            [...permDb.values()].find((p) => p.name === query.where.name) ??
              null,
          );
        }
        return Promise.resolve(null);
      },
    );
    mockPermissionRepository.find.mockResolvedValue([...permDb.values()]);
    mockPermissionRepository.create.mockImplementation(
      (data: Partial<Permission>) => ({ ...data }) as Permission,
    );
    mockPermissionRepository.save.mockImplementation((p: Permission) => {
      const saved: Permission = { ...p, id: p.id ?? `gen-perm-${Date.now()}` };
      permDb.set(saved.id, saved);
      return Promise.resolve(saved);
    });
    mockPermissionRepository.delete.mockImplementation((id: string) => {
      permDb.delete(id);
      return Promise.resolve({ affected: 1 });
    });
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // GET /user/me
  // =========================================================================

  describe('GET /user/me', () => {
    it('should return the authenticated user payload when a valid access token is present', async () => {
      const token = buildAccessToken(jwtService, REGULAR_USER);

      const response = await request(app.getHttpServer())
        .get('/api/user/me')
        .set('Cookie', [`access_token=${token}`])
        .expect(200);

      expect(response.body.id).toBe(REGULAR_USER.id);
      expect(response.body.email).toBe(REGULAR_USER.email);
    });

    it('should return 401 when no access token is provided', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/user/me')
        .expect(401);

      expect(response.body.message).toBe('User is not authenticated.');
    });

    it('should return the permissions array inside the user payload', async () => {
      const token = buildAccessToken(jwtService, ADMIN_USER);

      const response = await request(app.getHttpServer())
        .get('/api/user/me')
        .set('Cookie', [`access_token=${token}`])
        .expect(200);

      expect(Array.isArray(response.body.permissions)).toBe(true);
      expect(response.body.permissions[0].name).toBe('ADMIN');
    });
  });

  // =========================================================================
  // GET /permission
  // =========================================================================

  describe('GET /permission', () => {
    it('should return all permissions from the repository', async () => {
      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      const response = await request(app.getHttpServer())
        .get('/api/permission')
        .set('Cookie', [`access_token=${adminToken}`])
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      expect(response.body).toHaveLength(permDb.size);
    });

    it('should include both USER and ADMIN permissions in the response', async () => {
      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      const response = await request(app.getHttpServer())
        .get('/api/permission')
        .set('Cookie', [`access_token=${adminToken}`])
        .expect(200);

      const names: string[] = response.body.map((p: Permission) => p.name);
      expect(names).toContain('USER');
      expect(names).toContain('ADMIN');
    });

    it('should return an empty array when no permissions exist', async () => {
      permDb.clear();
      mockPermissionRepository.find.mockResolvedValue([]);

      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      const response = await request(app.getHttpServer())
        .get('/api/permission')
        .set('Cookie', [`access_token=${adminToken}`])
        .expect(200);

      expect(response.body).toEqual([]);
    });
  });

  // =========================================================================
  // POST /permission
  // =========================================================================

  describe('POST /permission', () => {
    it('should create a new permission with the name uppercased and return 201', async () => {
      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      const response = await request(app.getHttpServer())
        .post('/api/permission')
        .set('Cookie', [`access_token=${adminToken}`])
        .send({ name: 'moderator', description: 'Can moderate content' })
        .expect(201);

      expect(response.body.message).toMatch(/Permission 'MODERATOR' created/);
      expect(response.body.permission).toBeDefined();
      expect(response.body.permission.name).toBe('MODERATOR');
    });

    it('should uppercase the permission name before persisting it', async () => {
      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      await request(app.getHttpServer())
        .post('/api/permission')
        .set('Cookie', [`access_token=${adminToken}`])
        .send({ name: 'viewer', description: 'Viewer permission' })
        .expect(201);

      const saveCallArg = mockPermissionRepository.save.mock
        .calls[0][0] as Permission;
      expect(saveCallArg.name).toBe('VIEWER');
    });

    it('should return 409 when the repository raises a duplicate-entry error (PostgreSQL code 23505)', async () => {
      const dbError: Error & { code?: string } = Object.assign(
        new Error('Duplicate entry'),
        {
          code: '23505',
        },
      );
      mockPermissionRepository.save.mockRejectedValueOnce(dbError);

      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      const response = await request(app.getHttpServer())
        .post('/api/permission')
        .set('Cookie', [`access_token=${adminToken}`])
        .send({ name: 'USER', description: 'User role' })
        .expect(409);

      expect(response.body.message).toMatch(/already exists/);
    });

    it('should return 500 when an unexpected error occurs during creation', async () => {
      mockPermissionRepository.save.mockRejectedValueOnce(
        new Error('Unknown DB error'),
      );

      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      const response = await request(app.getHttpServer())
        .post('/api/permission')
        .set('Cookie', [`access_token=${adminToken}`])
        .send({ name: 'BROKEN', description: 'Broken perm' })
        .expect(500);

      expect(response.body.message).toBe('Error creating permission');
    });
  });

  // =========================================================================
  // PUT /permission/:id
  // =========================================================================

  describe('PUT /permission/:id', () => {
    it('should update an existing permission and return 200 with the updated entity', async () => {
      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      const response = await request(app.getHttpServer())
        .put(`/api/permission/${USER_PERMISSION.id}`)
        .set('Cookie', [`access_token=${adminToken}`])
        .send({ description: 'Updated description' })
        .expect(200);

      expect(response.body.id).toBe(USER_PERMISSION.id);
      expect(response.body.description).toBe('Updated description');
    });

    it('should return 404 when the permission id does not exist', async () => {
      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      const response = await request(app.getHttpServer())
        .put(`/api/permission/${NON_EXISTENT_UUID}`)
        .set('Cookie', [`access_token=${adminToken}`])
        .send({ description: 'Anything' })
        .expect(404);

      expect(response.body.message).toMatch(/not found/i);
    });

    it('should return 400 when sent a non-string name (class-validator on UpdatePermissionDTO)', async () => {
      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      await request(app.getHttpServer())
        .put(`/api/permission/${USER_PERMISSION.id}`)
        .set('Cookie', [`access_token=${adminToken}`])
        .send({ name: 1234 })
        .expect(400);
    });

    it('should accept a partial body (all UpdatePermissionDTO fields are optional)', async () => {
      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      const response = await request(app.getHttpServer())
        .put(`/api/permission/${ADMIN_PERMISSION.id}`)
        .set('Cookie', [`access_token=${adminToken}`])
        .send({ description: 'Elevated access' })
        .expect(200);

      expect(response.body.description).toBe('Elevated access');
    });
  });

  // =========================================================================
  // DELETE /permission/:id
  // =========================================================================

  describe('DELETE /permission/:id', () => {
    it('should delete a permission and return 200 with a confirmation message', async () => {
      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      const response = await request(app.getHttpServer())
        .delete(`/api/permission/${USER_PERMISSION.id}`)
        .set('Cookie', [`access_token=${adminToken}`])
        .expect(200);

      expect(response.body.message).toBe('Permission deleted');
    });

    it('should call repository.delete with the correct id', async () => {
      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      await request(app.getHttpServer())
        .delete(`/api/permission/${ADMIN_PERMISSION.id}`)
        .set('Cookie', [`access_token=${adminToken}`])
        .expect(200);

      expect(mockPermissionRepository.delete).toHaveBeenCalledWith(
        ADMIN_PERMISSION.id,
      );
    });

    it('should return 404 when the permission id does not exist', async () => {
      const adminToken = buildAccessToken(jwtService, ADMIN_USER);
      const response = await request(app.getHttpServer())
        .delete(`/api/permission/${NON_EXISTENT_UUID}`)
        .set('Cookie', [`access_token=${adminToken}`])
        .expect(404);

      expect(response.body.message).toMatch(/not found/i);
    });
  });
});
