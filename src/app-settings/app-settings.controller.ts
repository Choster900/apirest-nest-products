import { Controller, Get, Patch, Body, ValidationPipe, UsePipes } from '@nestjs/common';
import { AppSettingsService } from './app-settings.service';
import { UpdateAllSettingsDto } from './dto';
import { AppSettings } from './entities/app-settings.entity';

@Controller('admin/app-settings')
@UsePipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true
}))
export class AppSettingsController {
  constructor(private readonly appSettingsService: AppSettingsService) {}

  @Get()
  async getSettings(): Promise<AppSettings> {
    return this.appSettingsService.get();
  }

  @Patch()
  async updateSettings(
    @Body() updateDto: UpdateAllSettingsDto,
  ): Promise<AppSettings> {
    return this.appSettingsService.updateSettings(updateDto);
  }

  @Patch('logout-all')
  async logoutAllUsers(): Promise<AppSettings> {
    return this.appSettingsService.incrementGlobalSessionVersion();
  }
}
