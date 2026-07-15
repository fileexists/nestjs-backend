/**
 * app.e2e-spec.ts
 *
 * Smoke test – verifies the NestJS application bootstraps without errors
 * when all external dependencies (PostgreSQL, guards) are replaced with mocks.
 *
 * Run with: yarn test:e2e
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, CanActivate } from '@nestjs/common';
import * as request from 'supertest';
import { DataSource } from 'typeorm';
import { getRepositoryToken } from '@nestjs/typeorm';
import { AppModule } from './../src/app.module';
import { User } from './../src/common/entities/user.entity';
import { Permission } from './../src/common/entities/permission.entity';
import { AuthGuard } from './../src/common/guards/auth.guard';
import { PermissionsGuard } from './../src/common/guards/permissions.guard';
import { ThrottlerGuard } from '@nestjs/throttler';

describe('AppModule bootstrap (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(DataSource)
      .useValue({
        initialize: jest.fn().mockResolvedValue(undefined),
        destroy: jest.fn().mockResolvedValue(undefined),
      })
      .overrideProvider(getRepositoryToken(User))
      .useValue({
        findOne: jest.fn(),
        find: jest.fn(),
        save: jest.fn(),
        create: jest.fn(),
        delete: jest.fn(),
        update: jest.fn(),
      })
      .overrideProvider(getRepositoryToken(Permission))
      .useValue({
        findOne: jest.fn(),
        find: jest.fn(),
        save: jest.fn(),
        create: jest.fn(),
        delete: jest.fn(),
        update: jest.fn(),
      })
      .overrideProvider(AuthGuard)
      .useValue({ canActivate: () => true } as CanActivate)
      .overrideProvider(PermissionsGuard)
      .useValue({ canActivate: () => true } as CanActivate)
      .overrideProvider(ThrottlerGuard)
      .useValue({ canActivate: () => true } as CanActivate)
      .compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api', { exclude: ['health'] });
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('should start and respond to /health with 200', async () => {
    await request(app.getHttpServer()).get('/health').expect(200);
  });

  it('should respond to unknown routes with 404 (not 500)', async () => {
    await request(app.getHttpServer()).get('/non-existent-route').expect(404);
  });
});
