import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import type { App } from 'supertest/types';

export function req(app: INestApplication): ReturnType<typeof request> {
  return request(app.getHttpServer() as App);
}

export interface ApiResponseBody {
  message?: string;
  userId?: string;
  success?: boolean;
  user?: Record<string, unknown>;
  permission?: Record<string, unknown>;
  [key: string]: unknown;
}
