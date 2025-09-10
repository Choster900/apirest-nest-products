import { applyDecorators, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtAuthGuard } from '../guards';

export function Auth() {
    return applyDecorators(
        UseGuards(JwtAuthGuard),
    );
}
