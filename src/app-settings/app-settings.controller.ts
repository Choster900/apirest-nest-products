import { Controller, Get, Patch, Body } from '@nestjs/common';
import { AppSettingsService } from './app-settings.service';
import { UpdateAllowMultipleSessionsDto } from './dto/update-allow-multiple-sessions.dto';
import { UpdateDefaultsDto } from './dto/update-defaults.dto';
import { AppSettings } from './entities/app-settings.entity';

@Controller('admin/app-settings')
export class AppSettingsController {
  constructor(private readonly appSettingsService: AppSettingsService) {}

  @Get()
  async getSettings(): Promise<AppSettings> {
    return this.appSettingsService.get();
  }

  @Patch('allow-multiple-sessions')
  async updateAllowMultipleSessions(
    @Body() updateDto: UpdateAllowMultipleSessionsDto,
  ): Promise<AppSettings> {
    return this.appSettingsService.updateAllowMultipleSessions(updateDto);
  }

  @Patch('defaults')
  async updateDefaults(
    @Body() updateDto: UpdateDefaultsDto,
  ): Promise<AppSettings> {
    return this.appSettingsService.updateDefaults(updateDto);
  }

  @Patch('logout-all')
  async logoutAllUsers(): Promise<AppSettings> {
    return this.appSettingsService.incrementGlobalSessionVersion();
  }
}
