import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { Request } from 'express';

@Injectable()
export class FlexibleAuthGuard implements CanActivate {
    constructor(private authService: AuthService) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest<Request>();
        let token: string | undefined;

        // Intentar obtener el token desde cookie primero
        if (request.cookies?.['secure_token']) {
            token = request.cookies['secure_token'];
        }
        // Si no hay cookie, intentar desde Authorization header
        else {
            const authHeader = request.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer ')) {
                token = authHeader.substring(7);
            }
        }

        if (!token) {
            throw new UnauthorizedException('No authentication token found in cookies or Authorization header');
        }

        try {
            // Validar el token usando AuthService
            const authResult = await this.authService.verifyJwtToken(token);
            
            // Adjuntar información del usuario al request para uso en el controlador
            request['user'] = authResult;
            request['token'] = token;
            
            return true;
        } catch (error) {
            throw new UnauthorizedException('Invalid or expired token');
        }
    }
}