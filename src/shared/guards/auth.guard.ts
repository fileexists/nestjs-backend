import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
import * as dotenv from 'dotenv';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { AuthService } from '../../features/auth/auth.service';
dotenv.config();

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private reflector: Reflector,
    private authService: AuthService,
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
    let token = this.extractTokenFromHeader(request);

    if (!token) {
      if(!request.cookies?.refresh_token) {
        throw new UnauthorizedException('User is not authenticated.');
      }
      return await this.handleTokenRefresh(request, response);
    }

    try {
      const payload = await this.jwtService.verifyAsync(token, { secret: process.env.JWT_SECRET });
      request.user = payload;
      return true;
    } catch (error) {
      console.error("JWT Verification Failed:", error.message);

      if (error.name === 'TokenExpiredError') {
        return await this.handleTokenRefresh(request, response);
      }

      throw new UnauthorizedException('User is not authenticated.');
    }
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.split(' ')[1];
    }
    return request.cookies?.access_token || undefined;
  }

  private async handleTokenRefresh(request: Request, response: Response): Promise<boolean> {
    const refreshToken = request.cookies?.refresh_token;

    if (!refreshToken) {
      throw new UnauthorizedException('User is not authenticated.');
    }

    try {
      const { token: newAccessToken, refreshToken: newRefreshToken } = await this.authService.refreshTokens(refreshToken);

      const { accessTokenOptions, refreshTokenOptions } = this.authService.getCookieOptions();
  
      response.cookie('access_token', newAccessToken, accessTokenOptions);
      response.cookie('refresh_token', newRefreshToken, refreshTokenOptions);

      const decoded = await this.authService.verifyJwtToken(newAccessToken);
      request.user = decoded;
      return true;
    } catch (error) {
      console.error("Refresh token verification failed:", error.message);
      throw new UnauthorizedException('User is not authenticated.');
    }
  }
}
