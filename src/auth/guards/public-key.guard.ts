import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { envs } from '../../config';

@Injectable()
export class PublicKeyGuard implements CanActivate {
    canActivate(context: ExecutionContext): boolean {
        const request = context.switchToHttp().getRequest();
        const publicKey = this.extractPublicKey(request);

        if (!publicKey) {
            throw new UnauthorizedException('Public key is required');
        }

        if (publicKey !== envs.PUBLIC_KEY) {
            throw new UnauthorizedException('Invalid public key');
        }

        return true;
    }

    private extractPublicKey(request: any): string | undefined {
        // Opción 1: Como Bearer token en Authorization header
        const authHeader = request.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            return authHeader.substring(7);
        }

        // Opción 2: Como header personalizado 'x-public-key'
        const publicKeyHeader = request.headers['x-public-key'];
        if (publicKeyHeader) {
            return publicKeyHeader;
        }

        // Opción 3: Como header personalizado 'public-key'
        const publicKey = request.headers['public-key'];
        if (publicKey) {
            return publicKey;
        }

        return undefined;
    }
}