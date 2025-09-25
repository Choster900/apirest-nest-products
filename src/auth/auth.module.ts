import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';

import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { User } from './entities/user.entity';
import { JwtStrategy } from './strategies/jwt.strategy';
import { Session } from './entities/sessions.entity';
import { AppSettings } from '../app-settings/entities/app-settings.entity';
import { AppSettingsModule } from '../app-settings/app-settings.module';
import { AppSettingsService } from '../app-settings/app-settings.service';
import { UserProcessor } from './user.processor';
import { BullModule } from '@nestjs/bull';

@Module({
    controllers: [AuthController],
    providers: [AuthService, JwtStrategy, UserProcessor],
    imports: [
        BullModule.registerQueue({
            name: 'users', // 👈 este nombre debe coincidir con el de @InjectQueue('users')
        }),
        ConfigModule,
        AppSettingsModule,
        TypeOrmModule.forFeature([User, Session, AppSettings]),
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.registerAsync({
            imports: [ConfigModule, AppSettingsModule],
            inject: [ConfigService, AppSettingsService],
            useFactory: async (configService: ConfigService, appSettingsService: AppSettingsService) => {
                const appSettings = await appSettingsService.get();
                return {
                    secret: configService.get('JWT_PRIVATE_SECRET') || configService.get('JWT_SECRET'),
                    signOptions: {
                        expiresIn: `${appSettings.defaultMaxSessionMinutes * 60}s` // convertir minutos a segundos
                    }
                }
            }
        })
    ],
    exports: [TypeOrmModule, JwtStrategy, PassportModule, JwtModule, AuthService]
})
export class AuthModule { }
