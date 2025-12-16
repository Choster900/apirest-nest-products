import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ServeStaticModule } from '@nestjs/serve-static';
// import { BullModule } from '@nestjs/bull'; // TEMPORALMENTE DESHABILITADO
import { join } from 'path';

import { envs } from './config';
import { CommonModule } from './common/common.module';
import { SeedModule } from './seed/seed.module';
import { AuthModule } from './auth/auth.module';
import { AppSettingsModule } from './app-settings/app-settings.module';
import { PushNotificationsModule } from './push-notifications/push-notifications.module';

@Module({
    imports: [
        ConfigModule.forRoot(),

        // Configuración de Bull para colas - TEMPORALMENTE DESHABILITADO
        /*
        BullModule.forRoot({
            redis: {
                host: envs.REDIS_HOST,
                port: envs.REDIS_PORT,
                password: envs.REDIS_PASSWORD || undefined,
                ...(envs.REDIS_TLS && {
                    tls: {
                        rejectUnauthorized: false
                    }
                }),
                connectTimeout: 10000,
                lazyConnect: true,
                enableReadyCheck: false,
                maxRetriesPerRequest: 3,
            },
        }),

        // Registrar cola de usuarios
        BullModule.registerQueue({
            name: 'users',
        }),
        */

        TypeOrmModule.forRoot({
            type: 'postgres',
            host: envs.POSTGRES_HOST,
            port: envs.POSTGRES_PORT,
            database: envs.POSTGRES_DB,
            username: envs.POSTGRES_USER,
            password: envs.POSTGRES_PASSWORD,
            autoLoadEntities: true,
            synchronize: true,
            ssl: {
                rejectUnauthorized: false, // 👈 necesario para Neon
            },
            extra: {
                connectionTimeoutMillis: 10000,
                idleTimeoutMillis: 30000,
                max: 10,
                statement_timeout: 30000,
                query_timeout: 30000,
            },
        }),
        CommonModule,
        SeedModule,
        AppSettingsModule,

        // Configurar carpeta pública
        ServeStaticModule.forRoot({
            rootPath: join(process.cwd(), 'public'), // Cambiar __dirname a process.cwd()
            serveStaticOptions: {
                index: false // Deshabilitar búsqueda automática de index.html
            }
        }),

        AuthModule,

        PushNotificationsModule
    ],
    controllers: [],
    providers: [],
})
export class AppModule { }
