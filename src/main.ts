import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { envs } from './config';
import { Logger, ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);

    app.setGlobalPrefix('api')

    // ✅ CONFIGURAR COOKIE PARSER PARA LEER COOKIES
    app.use(cookieParser());

    // ✅ APLICAR EL PIPE GLOBALMENTE
    app.useGlobalPipes(
        new ValidationPipe({
            transform: true,  // Convierte automáticamente los tipos
            whitelist: true,  // Elimina propiedades no definidas en los DTO
            forbidNonWhitelisted: true, // Lanza error si hay propiedades desconocidas
            transformOptions: {
                enableImplicitConversion: true,  // Convierte sin necesidad de `@Type`
            },
        }),
    );

    await app.listen(envs.PORT);

    const logger = new Logger('Bootstrap');

    logger.log(`Application is running on port ${envs.PORT}`);
}
bootstrap();
