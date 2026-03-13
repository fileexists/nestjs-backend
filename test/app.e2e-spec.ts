/**
 * app.e2e-spec.ts
 *
 * Smoke test – verifies the NestJS application bootstraps without errors
 * when all external dependencies (MySQL, guards) are replaced with mocks.
 *
 * Run with: yarn test:e2e
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, CanActivate } from '@nestjs/common';
import * as request from 'supertest';
import { DataSource } from 'typeorm';
import { getRepositoryToken } from '@nestjs/typeorm';
import { AppModule } from './../src/app.module';
import { User } from './../src/database/user.entity';
import { Permission } from './../src/database/permission.entity';
import { AuthGuard } from './../src/shared/guards/auth.guard';
import { PermissionsGuard } from './../src/shared/guards/permissions.guard';
import { ThrottlerGuard } from '@nestjs/throttler';

describe('AppModule bootstrap (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      // Prevent any real MySQL connection
      .overrideProvider(DataSource)
      .useValue({
        initialize: jest.fn().mockResolvedValue(undefined),
        destroy: jest.fn().mockResolvedValue(undefined),
      })
      // Minimal no-op repositories
      .overrideProvider(getRepositoryToken(User))
      .useValue({ findOne: jest.fn(), find: jest.fn(), save: jest.fn(), create: jest.fn(), delete: jest.fn(), update: jest.fn() })
      .overrideProvider(getRepositoryToken(Permission))
      .useValue({ findOne: jest.fn(), find: jest.fn(), save: jest.fn(), create: jest.fn(), delete: jest.fn(), update: jest.fn() })
      // Always-allow guard stubs
      .overrideProvider(AuthGuard)
      .useValue({ canActivate: () => true } as CanActivate)
      .overrideProvider(PermissionsGuard)
      .useValue({ canActivate: () => true } as CanActivate)
      .overrideProvider(ThrottlerGuard)
      .useValue({ canActivate: () => true } as CanActivate)
      .compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('should start the application and respond to unknown routes with 404 (not 500)', async () => {
    // A 404 proves the app is up and routing – any 5xx would indicate a crash.
    await request(app.getHttpServer())
      .get('/health-check-nonexistent')
      .expect(404);
  });
});
