import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { CookieOptions } from 'express';
import * as jwt from 'jsonwebtoken';
import * as ms from 'ms';
@Injectable()
export class AuthService {
  constructor(private jwtService: JwtService) {}

  private readonly jwtSecret = process.env.JWT_SECRET || 'your_jwt_secret';
  private readonly refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET || 'your_refresh_token_secret';
  private readonly jwtExpiration = process.env.JWT_EXPIRATION || '15m';
  private readonly refreshTokenExpiration = process.env.REFRESH_TOKEN_EXPIRATION || '7d';

  
  async hashPassword(password: string): Promise<string> {
    return await bcrypt.hash(password, 10);
  }

  async comparePasswords(plainPassword: string, hashedPassword: string): Promise<boolean> {
    return await bcrypt.compare(plainPassword, hashedPassword);
  }
  
  async generateJwtToken(user: any): Promise<string> {
    return this.jwtService.sign({ 
      id: user.id, 
      email: user.email, 
      permissions: user.permissions
    }, {
      secret: this.jwtSecret,
      expiresIn: this.jwtExpiration,
    });
  }  
  
  async generateRefreshToken(user: any): Promise<string> {
    return jwt.sign({ 
      id: user.id, 
      email: user.email, 
      permissions: user.permissions
    }, this.refreshTokenSecret, {
      expiresIn: this.refreshTokenExpiration,
    });
  }

  async verifyJwtToken(token: string): Promise<any> {
    try {
      return await this.jwtService.verify(token, { secret: this.jwtSecret });
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async refreshTokens(refreshToken: string): Promise<{ token: string; refreshToken: string }> {
    try {
      const decoded = jwt.verify(refreshToken, this.refreshTokenSecret);
      const newAccessToken = await this.generateJwtToken(decoded);
      const newRefreshToken = await this.generateRefreshToken(decoded);

      return { token: newAccessToken, refreshToken: newRefreshToken };
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  getCookieOptions(): {
    accessTokenOptions: CookieOptions;
    refreshTokenOptions: CookieOptions;
  } {
    const refreshOptions: CookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    };

    const cookieOptions: CookieOptions = {
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    };

    return {
      accessTokenOptions: {
        ...cookieOptions,
        maxAge: ms(this.jwtExpiration),
      },
      refreshTokenOptions: {
        ...refreshOptions,
        maxAge: ms(this.refreshTokenExpiration),
      },
    };
  }
}
