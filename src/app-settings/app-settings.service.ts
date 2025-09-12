import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { AppSettings } from './entities/app-settings.entity';
import { UpdateAllowMultipleSessionsDto } from './dto/update-allow-multiple-sessions.dto';
import { UpdateDefaultsDto } from './dto/update-defaults.dto';

@Injectable()
export class AppSettingsService {
  constructor(
    @InjectRepository(AppSettings)
    private readonly appSettingsRepository: Repository<AppSettings>,
    private readonly dataSource: DataSource,
  ) {}

  async get(): Promise<AppSettings> {
    let settings = await this.appSettingsRepository.findOne({ where: { id: 1 } });

    if (!settings) {
      // Create initial settings with defaults from environment
      settings = this.appSettingsRepository.create({
        id: 1,
        allowMultipleSessions: process.env.DEFAULT_ALLOW_MULTIPLE_SESSIONS !== 'false',
        globalSessionVersion: 0,
        defaultMaxSessionMinutes: Number(process.env.DEFAULT_MAX_SESSION_MINUTES ?? 60),
        isActive: true,
      });
      settings = await this.appSettingsRepository.save(settings);
    }

    return settings;
  }

  async updateAllowMultipleSessions(updateDto: UpdateAllowMultipleSessionsDto): Promise<AppSettings> {
    const { allowMultipleSessions, forceLogoutAll } = updateDto;

    return this.dataSource.transaction(async manager => {
      let settings = await manager.findOne(AppSettings, { where: { id: 1 } });

      if (!settings) {
        settings = manager.create(AppSettings, {
          id: 1,
          allowMultipleSessions,
          globalSessionVersion: 0,
          defaultMaxSessionMinutes: Number(process.env.DEFAULT_MAX_SESSION_MINUTES ?? 60),
          isActive: true,
        });
      } else {
        settings.allowMultipleSessions = allowMultipleSessions;
      }

      if (forceLogoutAll) {
        // Increment global session version to invalidate all existing JWTs
        settings.globalSessionVersion += 1;

        // Optional: Delete all physical sessions (aggressive cleanup)
        await manager.query('DELETE FROM sessions');
      }

      return manager.save(settings);
    });
  }

  async updateDefaults(updateDto: UpdateDefaultsDto): Promise<AppSettings> {
    const settings = await this.get();

    if (updateDto.defaultMaxSessionMinutes !== undefined) {
      settings.defaultMaxSessionMinutes = updateDto.defaultMaxSessionMinutes;
    }

    return this.appSettingsRepository.save(settings);
  }

  async incrementGlobalSessionVersion(): Promise<AppSettings> {
    const settings = await this.get();
    settings.globalSessionVersion += 1;
    return this.appSettingsRepository.save(settings);
  }
}
