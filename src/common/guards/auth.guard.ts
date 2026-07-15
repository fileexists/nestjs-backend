import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { AuthService } from '../../modules/auth/auth.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly reflector: Reflector,
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      if (!request.cookies?.refresh_token) {
        throw new UnauthorizedException('User is not authenticated.');
      }
      return this.handleTokenRefresh(request, response);
    }

    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>('JWT_SECRET'),
      });
      request.user = payload;
      return true;
    } catch (error: unknown) {
      if (error instanceof Error && error.name === 'TokenExpiredError') {
        return this.handleTokenRefresh(request, response);
      }
      throw new UnauthorizedException('User is not authenticated.');
    }
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const authHeader = request.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.split(' ')[1];
    }
    return request.cookies?.access_token ?? undefined;
  }

  private async handleTokenRefresh(
    request: Request,
    response: Response,
  ): Promise<boolean> {
    const refreshToken = request.cookies?.refresh_token;

    if (!refreshToken) {
      throw new UnauthorizedException('User is not authenticated.');
    }

    try {
      const { token: newAccessToken, refreshToken: newRefreshToken } =
        await this.authService.refreshTokens(refreshToken);

      const { accessTokenOptions, refreshTokenOptions } =
        this.authService.getCookieOptions();

      response.cookie('access_token', newAccessToken, accessTokenOptions);
      response.cookie('refresh_token', newRefreshToken, refreshTokenOptions);

      const decoded = await this.authService.verifyJwtToken(newAccessToken);
      request.user = decoded as Express.User;
      return true;
    } catch {
      throw new UnauthorizedException('User is not authenticated.');
    }
  }
}
