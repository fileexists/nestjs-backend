/**
 * auth.e2e-spec.ts
 *
 * End-to-end tests for the Auth HTTP layer.  The suite spins up the full
 * NestJS application but replaces every external dependency that would
 * require a live service (PostgreSQL, Google OAuth) with in-memory/mock
 * counterparts via NestJS module overrides.
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
import * as bcrypt from 'bcrypt';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { DataSource } from 'typeorm';
import { ThrottlerGuard } from '@nestjs/throttler';

import { AppModule } from '../src/app.module';
import { User } from '../src/common/entities/user.entity';
import { Permission } from '../src/common/entities/permission.entity';
import { AuthService } from '../src/modules/auth/auth.service';
import { AuthGuard } from '../src/common/guards/auth.guard';
import { PermissionsGuard } from '../src/common/guards/permissions.guard';
import { GoogleOAuthGuard } from '../src/common/guards/google-oauth.guard';

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

const USER_PERMISSION: Permission = {
  id: 'perm-user-uuid',
  name: 'USER',
  description: 'Default user permission',
  users: [],
};

const LOCAL_USER: User = {
  id: 'user-local-uuid',
  email: 'local@example.com',
  password: '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  provider: 'local',
  googleId: undefined,
  tokenVersion: 0,
  permissions: [USER_PERMISSION],
  createdAt: new Date(),
  updatedAt: new Date(),
};

const GOOGLE_USER: User = {
  id: 'user-google-uuid',
  email: 'google@example.com',
  password: undefined,
  provider: 'google',
  googleId: 'google-oauth-id-123',
  tokenVersion: 0,
  permissions: [USER_PERMISSION],
  createdAt: new Date(),
  updatedAt: new Date(),
};

// ---------------------------------------------------------------------------
// In-memory DB helpers
// ---------------------------------------------------------------------------

const db: Map<string, User> = new Map();

function resetDb(): void {
  db.clear();
  db.set(LOCAL_USER.email, { ...LOCAL_USER, permissions: [USER_PERMISSION] });
  db.set(GOOGLE_USER.email, { ...GOOGLE_USER, permissions: [USER_PERMISSION] });
}

// ---------------------------------------------------------------------------
// Mock repositories
// ---------------------------------------------------------------------------

const mockUserRepository = {
  findOne: jest.fn(({ where }: { where: Partial<User> }) => {
    if (where.email) return Promise.resolve(db.get(where.email) ?? null);
    if (where.id)
      return Promise.resolve(
        [...db.values()].find((u) => u.id === where.id) ?? null,
      );
    return Promise.resolve(null);
  }),
  find: jest.fn(() => Promise.resolve([...db.values()])),
  create: jest.fn((data: Partial<User>) => ({ ...data }) as User),
  save: jest.fn((user: User) => {
    const saved: User = {
      id: user.id ?? `generated-uuid-${Date.now()}`,
      email: user.email,
      password: user.password,
      googleId: user.googleId,
      provider: user.provider,
      tokenVersion: user.tokenVersion ?? 0,
      permissions: user.permissions ?? [],
      createdAt: user.createdAt ?? new Date(),
      updatedAt: new Date(),
    };
    db.set(saved.email, saved);
    return Promise.resolve(saved);
  }),
  update: jest.fn((id: string, data: Partial<User>) => {
    const existing = [...db.values()].find((u) => u.id === id);
    if (existing) {
      Object.assign(existing, data);
      db.set(existing.email, existing);
    }
    return Promise.resolve({ affected: 1 });
  }),
  delete: jest.fn(() => Promise.resolve({ affected: 1 })),
};

const mockPermissionRepository = {
  findOne: jest.fn((query: { where: Partial<Permission> }) => {
    if (query.where.name === 'USER') return Promise.resolve(USER_PERMISSION);
    return Promise.resolve(null);
  }),
  find: jest.fn(() => Promise.resolve([USER_PERMISSION])),
  create: jest.fn((data: Partial<Permission>) => ({ ...data }) as Permission),
  save: jest.fn((p: Permission) => Promise.resolve(p)),
  update: jest.fn(() => Promise.resolve({ affected: 1 })),
  delete: jest.fn(() => Promise.resolve({ affected: 1 })),
};

const mockDataSource = {
  initialize: jest.fn().mockResolvedValue(undefined),
  destroy: jest.fn().mockResolvedValue(undefined),
};

// ---------------------------------------------------------------------------
// Bootstrap helpers
// ---------------------------------------------------------------------------

function buildValidAccessToken(
  app: INestApplication,
  userPayload: object,
): string {
  const jwtService = app.get(JwtService);
  return jwtService.sign(userPayload, {
    secret: process.env.JWT_SECRET ?? 'your_jwt_secret',
    expiresIn: '15m',
  });
}

async function buildValidRefreshToken(
  app: INestApplication,
  user: User,
): Promise<string> {
  const authService = app.get(AuthService);
  return authService.generateRefreshToken(user);
}

async function createGoogleOverrideApp(
  userPayload: unknown,
): Promise<INestApplication> {
  const googleGuardStub: CanActivate = {
    canActivate: (context: ExecutionContext) => {
      const req = context.switchToHttp().getRequest();
      req.user = userPayload;
      return true;
    },
  };

  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  })
    .overrideProvider(DataSource)
    .useValue(mockDataSource)
    .overrideProvider(getRepositoryToken(User))
    .useValue(mockUserRepository)
    .overrideProvider(getRepositoryToken(Permission))
    .useValue(mockPermissionRepository)
    .overrideProvider('THROTTLER:MODULE_OPTIONS')
    .useValue([{ ttl: 60000, limit: 99999 }])
    .overrideProvider(AuthGuard)
    .useValue({ canActivate: () => Promise.resolve(true) } as CanActivate)
    .overrideProvider(PermissionsGuard)
    .useValue({ canActivate: () => Promise.resolve(true) } as CanActivate)
    .overrideProvider(ThrottlerGuard)
    .useValue({ canActivate: () => Promise.resolve(true) } as CanActivate)
    .overrideGuard(GoogleOAuthGuard)
    .useValue(googleGuardStub)
    .compile();

  const customApp = moduleFixture.createNestApplication();
  customApp.setGlobalPrefix('api', { exclude: ['health'] });
  customApp.use(cookieParser());
  await customApp.init();
  return customApp;
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

describe('AuthController (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(DataSource)
      .useValue(mockDataSource)
      .overrideProvider(getRepositoryToken(User))
      .useValue(mockUserRepository)
      .overrideProvider(getRepositoryToken(Permission))
      .useValue(mockPermissionRepository)
      .overrideProvider('THROTTLER:MODULE_OPTIONS')
      .useValue([{ ttl: 60000, limit: 99999 }])
      .overrideProvider(AuthGuard)
      .useValue({ canActivate: () => Promise.resolve(true) } as CanActivate)
      .overrideProvider(PermissionsGuard)
      .useValue({ canActivate: () => Promise.resolve(true) } as CanActivate)
      .overrideProvider(ThrottlerGuard)
      .useValue({ canActivate: () => Promise.resolve(true) } as CanActivate)
      .compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api', { exclude: ['health'] });
    app.use(cookieParser());
    app.useGlobalPipes(
      new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }),
    );
    await app.init();
  });

  beforeEach(() => {
    resetDb();
    jest.clearAllMocks();

    mockUserRepository.findOne.mockImplementation(
      ({ where }: { where: Partial<User> }) => {
        if (where.email) return Promise.resolve(db.get(where.email) ?? null);
        if (where.id)
          return Promise.resolve(
            [...db.values()].find((u) => u.id === where.id) ?? null,
          );
        return Promise.resolve(null);
      },
    );
    mockUserRepository.find.mockResolvedValue([...db.values()]);
    mockUserRepository.create.mockImplementation(
      (data: Partial<User>) => ({ ...data }) as User,
    );
    mockUserRepository.save.mockImplementation((user: User) => {
      const saved: User = {
        id: user.id ?? `generated-uuid-${Date.now()}`,
        email: user.email,
        password: user.password,
        googleId: user.googleId,
        provider: user.provider,
        tokenVersion: user.tokenVersion ?? 0,
        permissions: user.permissions ?? [],
        createdAt: user.createdAt ?? new Date(),
        updatedAt: new Date(),
      };
      db.set(saved.email, saved);
      return Promise.resolve(saved);
    });
    mockUserRepository.update.mockImplementation(
      (id: string, data: Partial<User>) => {
        const existing = [...db.values()].find((u) => u.id === id);
        if (existing) {
          Object.assign(existing, data);
          db.set(existing.email, existing);
        }
        return Promise.resolve({ affected: 1 });
      },
    );
    mockPermissionRepository.findOne.mockImplementation(
      (query: { where: Partial<Permission> }) => {
        if (query.where.name === 'USER')
          return Promise.resolve(USER_PERMISSION);
        return Promise.resolve(null);
      },
    );
    mockPermissionRepository.find.mockResolvedValue([USER_PERMISSION]);
    mockPermissionRepository.save.mockImplementation((p: Permission) =>
      Promise.resolve(p),
    );
  });

  afterAll(async () => {
    await app.close();
  });

  // =========================================================================
  // POST /auth/logout
  // =========================================================================

  describe('POST /api/auth/logout', () => {
    it('should return 200 and clear both cookies', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/logout')
        .expect(200);

      expect(response.body.message).toBe(
        'User has been logged out successfully.',
      );

      const setCookieHeaders: string[] =
        (response.headers['set-cookie'] as unknown as string[]) ?? [];
      const serialized = setCookieHeaders.join(';');
      expect(serialized).toMatch(/access_token/);
      expect(serialized).toMatch(/refresh_token/);
    });
  });

  // =========================================================================
  // POST /auth/register
  // =========================================================================

  describe('POST /auth/register', () => {
    it('should return 201 and the new userId when registering a brand-new email', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/register')
        .send({ email: 'newuser@example.com', password: 'StrongPass1!' })
        .expect(201);

      expect(response.body.message).toBe('User registered successfully');
      expect(response.body.userId).toBeDefined();
      expect(typeof response.body.userId).toBe('string');
    });

    it('should store a bcrypt-hashed password (not plain text) in the repository', async () => {
      await request(app.getHttpServer())
        .post('/api/auth/register')
        .send({ email: 'hashed@example.com', password: 'PlainText123' })
        .expect(201);

      const savedUser = db.get('hashed@example.com')!;
      expect(savedUser.password).not.toBe('PlainText123');
      expect(savedUser.password?.startsWith('$2b$')).toBe(true);
    });

    it('should assign the USER permission to the newly created account', async () => {
      await request(app.getHttpServer())
        .post('/api/auth/register')
        .send({ email: 'withperm@example.com', password: 'Pass1234!' })
        .expect(201);

      const savedUser = db.get('withperm@example.com')!;
      expect(savedUser.permissions).toEqual([USER_PERMISSION]);
    });

    it('should return 400 when the email is already registered', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/register')
        .send({ email: LOCAL_USER.email, password: 'AnyPassword1' })
        .expect(400);

      expect(response.body.message).toBe('User already registered');
    });
  });

  // =========================================================================
  // POST /auth/login
  // =========================================================================

  describe('POST /auth/login', () => {
    it('should return 200 and set access_token + refresh_token cookies on valid credentials', async () => {
      const plainPassword = 'icRIIke.';
      const hash = await bcrypt.hash(plainPassword, 10);
      db.set(LOCAL_USER.email, { ...LOCAL_USER, password: hash });

      const response = await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({ email: LOCAL_USER.email, password: plainPassword })
        .expect(200);

      expect(response.body.message).toBe('Login successful.');

      const cookies: string[] =
        (response.headers['set-cookie'] as unknown as string[]) ?? [];
      const joined = cookies.join(' ');
      expect(joined).toMatch(/access_token/);
      expect(joined).toMatch(/refresh_token/);
    });

    it('should return 401 when the email does not exist', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({ email: 'nobody@example.com', password: 'anything' })
        .expect(401);

      expect(response.body.message).toBe('Invalid email or password');
    });

    it('should return 401 when the password is incorrect', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({ email: LOCAL_USER.email, password: 'WrongPassword!' })
        .expect(401);

      expect(response.body.message).toBe('Invalid email or password');
    });

    it('should return 401 when a Google-only user tries to login with a password', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({ email: GOOGLE_USER.email, password: 'anypassword' })
        .expect(401);

      expect(response.body.message).toBe('Please login via google.');
    });

    it('should update provider to "combined" when a google user logs in with a password', async () => {
      const password = 'Password1!';
      const hash = await bcrypt.hash(password, 10);
      const combinedUser: User = {
        ...GOOGLE_USER,
        password: hash,
        provider: 'google',
      };
      db.set(combinedUser.email, combinedUser);

      await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({ email: combinedUser.email, password })
        .expect(200);

      const updated = db.get(combinedUser.email)!;
      expect(updated.provider).toBe('combined');
    });

    it('should return 401 when the request body is missing the password field', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/login')
        .send({ email: LOCAL_USER.email })
        .expect(401);

      expect(response.body.message).toBe('Invalid email or password');
    });
  });

  // =========================================================================
  // GET /auth/validate
  // =========================================================================

  describe('GET /auth/validate', () => {
    it('should return 200 and { success: true } when a valid access_token cookie is present', async () => {
      const token = buildValidAccessToken(app, {
        id: LOCAL_USER.id,
        email: LOCAL_USER.email,
        permissions: LOCAL_USER.permissions,
      });

      const response = await request(app.getHttpServer())
        .get('/api/auth/validate')
        .set('Cookie', [`access_token=${token}`])
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    it('should return 401 when no tokens are present at all', async () => {
      await request(app.getHttpServer()).get('/api/auth/validate').expect(401);
    });

    it('should refresh tokens and return { success: true } when only a valid refresh_token cookie is present', async () => {
      const refreshToken = await buildValidRefreshToken(app, LOCAL_USER);

      const response = await request(app.getHttpServer())
        .get('/api/auth/validate')
        .set('Cookie', [`refresh_token=${refreshToken}`])
        .expect(200);

      expect(response.body.success).toBe(true);

      const setCookieHeaders: string[] =
        (response.headers['set-cookie'] as unknown as string[]) ?? [];
      const joined = setCookieHeaders.join(' ');
      expect(joined).toMatch(/access_token/);
      expect(joined).toMatch(/refresh_token/);
    });

    it('should return 401 when both the access_token and refresh_token are expired/invalid', async () => {
      await request(app.getHttpServer())
        .get('/api/auth/validate')
        .set('Cookie', [
          'access_token=invalid.token; refresh_token=invalid.refresh',
        ])
        .expect(401);
    });

    it('should return 401 when only a malformed access_token is present and no refresh_token exists', async () => {
      await request(app.getHttpServer())
        .get('/api/auth/validate')
        .set('Cookie', ['access_token=this.is.garbage'])
        .expect(401);
    });
  });

  // =========================================================================
  // GET /auth/google
  // =========================================================================

  describe('GET /auth/google', () => {
    it('should redirect to the Google OAuth consent page (302)', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/auth/google')
        .redirects(0);

      expect([301, 302, 303, 307, 308]).toContain(response.status);
    });
  });

  // =========================================================================
  // GET /auth/google/callback
  // =========================================================================

  describe('GET /auth/google/callback', () => {
    it('should create a new user and return 200 when the Google account has no prior record', async () => {
      const overriddenApp = await createGoogleOverrideApp({
        googleId: 'brand-new-google-id',
        email: 'brandnew@gmail.com',
        name: 'Brand New',
      });

      const response = await request(overriddenApp.getHttpServer())
        .get('/api/auth/google/callback')
        .expect(200);

      expect(response.body.message).toBe(
        'Authentication with google was successful.',
      );

      const cookies: string[] =
        (response.headers['set-cookie'] as unknown as string[]) ?? [];
      expect(cookies.join(' ')).toMatch(/access_token/);

      await overriddenApp.close();
    });

    it('should update googleId and return 200 when an existing local user signs in with Google', async () => {
      const localUserWithoutGoogle: User = {
        ...LOCAL_USER,
        googleId: undefined,
      };
      db.set(LOCAL_USER.email, localUserWithoutGoogle);

      const overriddenApp = await createGoogleOverrideApp({
        googleId: 'new-google-id-for-local',
        email: LOCAL_USER.email,
        name: 'Local User',
      });

      const response = await request(overriddenApp.getHttpServer())
        .get('/api/auth/google/callback')
        .expect(200);

      expect(response.body.message).toBe(
        'Authentication with google was successful.',
      );

      await overriddenApp.close();
    });
  });
});
