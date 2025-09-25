import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppSettingsController } from './app-settings.controller';
import { AppSettingsService } from './app-settings.service';
import { AppSettings } from './entities/app-settings.entity';
import { Session } from '../auth/entities/sessions.entity';

@Module({
  imports: [TypeOrmModule.forFeature([AppSettings, Session])],
  controllers: [AppSettingsController],
  providers: [AppSettingsService],
  exports: [AppSettingsService],
})
export class AppSettingsModule {}
