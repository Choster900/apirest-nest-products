import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { envs } from '../../config';
import { Request } from 'express';

@Injectable()
export class RefreshTokenGuard implements CanActivate {
    constructor(private jwtService: JwtService) {}

    canActivate(context: ExecutionContext): boolean {
        const request = context.switchToHttp().getRequest<Request>();
        let refreshToken: string | undefined;

        // Intentar obtener refresh token desde cookie primero
        if (request.cookies?.['secure_refresh_token']) {
            refreshToken = request.cookies['secure_refresh_token'];
        }
        // Si no hay cookie, intentar desde Authorization header
        else {
            const authHeader = request.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer ')) {
                refreshToken = authHeader.substring(7);
            }
        }

        if (!refreshToken) {
            throw new UnauthorizedException('Refresh token not found in cookies or Authorization header');
        }

        try {
            // Verificar que el refresh token sea válido y tenga el tipo correcto
            const payload = this.jwtService.verify(refreshToken, {
                secret: envs.JWT_PRIVATE_SECRET
            });

            // Verificar que sea un refresh token
            if (payload.type !== 'refresh') {
                throw new UnauthorizedException('Invalid token type, expected refresh token');
            }

            // Adjuntar payload al request
            request['user'] = payload;
            request['refreshToken'] = refreshToken;
            
            return true;
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new UnauthorizedException('Refresh token has expired');
            }
            if (error.name === 'JsonWebTokenError') {
                throw new UnauthorizedException('Invalid refresh token');
            }
            throw new UnauthorizedException('Refresh token validation failed');
        }
    }
}