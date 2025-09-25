import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { envs } from '../../config';
import { Request } from 'express';

@Injectable()
export class CookieAuthGuard implements CanActivate {
    constructor(private jwtService: JwtService) {}

    canActivate(context: ExecutionContext): boolean {
        const request = context.switchToHttp().getRequest<Request>();
        const token = this.extractTokenFromCookie(request);

        if (!token) {
            throw new UnauthorizedException('Authentication token not found in cookies');
        }

        try {
            const payload = this.jwtService.verify(token, {
                secret: envs.JWT_PRIVATE_SECRET
            });

            // Attach payload to request for use in controller
            request['user'] = payload;
            request['token'] = token;
            
            return true;
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new UnauthorizedException('Authentication token has expired');
            }
            if (error.name === 'JsonWebTokenError') {
                throw new UnauthorizedException('Invalid authentication token');
            }
            throw new UnauthorizedException('Token validation failed');
        }
    }

    private extractTokenFromCookie(request: Request): string | undefined {
        return request.cookies?.['secure_token'];
    }
}