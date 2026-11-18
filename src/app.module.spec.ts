import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard } from '@nestjs/throttler';
import { AuthGuard } from './common/guards/auth.guard';
import { PermissionsGuard } from './common/guards/permissions.guard';
import { AppModule } from './app.module';

describe('AppModule global guards', () => {
  it('run in this order: rate limit, authentication, permissions', () => {
    const providers = Reflect.getMetadata('providers', AppModule) as {
      provide?: unknown;
      useExisting?: unknown;
    }[];

    const order = providers
      .filter((p) => p.provide === APP_GUARD)
      .map((p) => p.useExisting);

    // Nest runs APP_GUARDs in registration order. The throttler has to see the requests that the
    // other two reject, otherwise anonymous traffic on protected routes is never limited.
    expect(order).toEqual([ThrottlerGuard, AuthGuard, PermissionsGuard]);
  });
});
