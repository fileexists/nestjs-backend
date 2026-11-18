import { ConfigService } from '@nestjs/config';
import { NestExpressApplication } from '@nestjs/platform-express';
import { Reflector } from '@nestjs/core';
import { configureApp, trustProxyHops } from './app.setup';

function appWith(trustProxy: unknown) {
  const set = jest.fn();
  const app = {
    set,
    setGlobalPrefix: jest.fn(),
    use: jest.fn(),
    useGlobalPipes: jest.fn(),
    useGlobalFilters: jest.fn(),
    useGlobalInterceptors: jest.fn(),
    get: jest.fn((token: unknown) =>
      token === ConfigService
        ? {
            get: (key: string) =>
              key === 'TRUST_PROXY' ? trustProxy : undefined,
          }
        : new Reflector(),
    ),
  };
  return { app: app as unknown as NestExpressApplication, set };
}

describe('trustProxyHops', () => {
  it.each([
    [undefined, 1],
    [1, 1],
    [2, 2],
    ['3', 3],
  ])('TRUST_PROXY=%j -> trusts %i hop(s)', (value, hops) => {
    expect(trustProxyHops(appWith(value).app)).toBe(hops);
  });

  it('0 means no proxy: Express gets false and ignores X-Forwarded-For', () => {
    expect(trustProxyHops(appWith(0).app)).toBe(false);
    expect(trustProxyHops(appWith('0').app)).toBe(false);
  });
});

describe('configureApp', () => {
  it('applies TRUST_PROXY to Express instead of a fixed value', () => {
    const one = appWith(2);
    configureApp(one.app);
    expect(one.set).toHaveBeenCalledWith('trust proxy', 2);

    const none = appWith(0);
    configureApp(none.app);
    expect(none.set).toHaveBeenCalledWith('trust proxy', false);
  });
});
