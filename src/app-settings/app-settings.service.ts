import { Injectable, Logger, BadRequestException, InternalServerErrorException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { AppSettings } from './entities/app-settings.entity';
import { Session } from '../auth/entities/sessions.entity';
import { UpdateAllSettingsDto } from './dto';

@Injectable()
export class AppSettingsService {
  private readonly logger = new Logger('AppSettingsService');

  constructor(
    @InjectRepository(AppSettings)
    private readonly appSettingsRepository: Repository<AppSettings>,
    @InjectRepository(Session)
    private readonly sessionRepository: Repository<Session>,
    private readonly dataSource: DataSource,
  ) { }

  async get(): Promise<AppSettings> {
    try {
      let settings = await this.appSettingsRepository.findOne({ where: { id: 1 } });

      if (!settings) {
        this.logger.log('Creating initial app settings with default values');
        // Create initial settings with defaults from environment
        settings = this.appSettingsRepository.create({
          id: 1,
          allowMultipleSessions: process.env.DEFAULT_ALLOW_MULTIPLE_SESSIONS !== 'false',
          globalSessionVersion: 0,
          defaultMaxSessionMinutes: Number(process.env.DEFAULT_MAX_SESSION_MINUTES ?? 60),
        });
        settings = await this.appSettingsRepository.save(settings);
        this.logger.log('Initial app settings created successfully');
      }

      return settings;
    } catch (error) {
      this.logger.error('Error getting app settings:', error);
      throw new InternalServerErrorException('Failed to retrieve app settings');
    }
  }

  async updateSettings(updateDto: UpdateAllSettingsDto): Promise<AppSettings> {
    try {
      this.logger.log(`Updating settings: ${JSON.stringify(updateDto)}`);

      return this.dataSource.transaction(async manager => {
        let settings = await manager.findOne(AppSettings, { where: { id: 1 } });
        const currentAllowMultipleSessions = settings?.allowMultipleSessions;

        if (!settings) {
          // Create initial settings if they don't exist
          settings = manager.create(AppSettings, {
            id: 1,
            allowMultipleSessions: updateDto.allowMultipleSessions ?? true,
            globalSessionVersion: 0,
            defaultMaxSessionMinutes: updateDto.defaultMaxSessionMinutes ?? 60,
            loginBlockDurationMinutes: updateDto.loginBlockDurationMinutes ?? 5,
            maxLoginAttempts: updateDto.maxLoginAttempts ?? 3,
          });
        } else {
          // Update existing settings only with provided values
          if (updateDto.allowMultipleSessions !== undefined) {
            settings.allowMultipleSessions = updateDto.allowMultipleSessions;
          }
          if (updateDto.defaultMaxSessionMinutes !== undefined) {
            settings.defaultMaxSessionMinutes = updateDto.defaultMaxSessionMinutes;
          }
          if (updateDto.loginBlockDurationMinutes !== undefined) {
            settings.loginBlockDurationMinutes = updateDto.loginBlockDurationMinutes;
          }
          if (updateDto.maxLoginAttempts !== undefined) {
            settings.maxLoginAttempts = updateDto.maxLoginAttempts;
          }
        }

        // Handle session state changes when allowMultipleSessions changes
        if (updateDto.allowMultipleSessions !== undefined &&
          currentAllowMultipleSessions !== updateDto.allowMultipleSessions) {

          if (updateDto.allowMultipleSessions === false) {
            // Disable multiple sessions - deactivate all sessions
            this.logger.log('Disabling multiple sessions - deactivating all user sessions');
            const deactivatedSessions = await manager.update(
              Session,
              { isActive: true },
              { isActive: false }
            );
            this.logger.log(`Deactivated ${deactivatedSessions.affected || 0} sessions`);

            // Increment session version to invalidate existing JWTs
            settings.globalSessionVersion += 1;
            this.logger.log('Global session version incremented due to multiple sessions disabled');

          } else {
            // Enable multiple sessions - users can now have multiple active sessions
            this.logger.log('Multiple sessions enabled - users can now have multiple active sessions');
          }
        }

        if (updateDto.forceLogoutAll) {
          this.logger.log('Force logout all users requested');
          // Increment global session version to invalidate all existing JWTs
          settings.globalSessionVersion += 1;
        }

        const result = await manager.save(settings);
        this.logger.log('Settings updated successfully');
        return result;
      });
    } catch (error) {
      this.logger.error('Error updating settings:', error);
      throw new InternalServerErrorException('Failed to update application settings');
    }
  } async incrementGlobalSessionVersion(): Promise<AppSettings> {
    try {
      this.logger.log('Incrementing global session version');
      const settings = await this.get();
      settings.globalSessionVersion += 1;
      const result = await this.appSettingsRepository.save(settings);
      this.logger.log(`Global session version incremented to: ${result.globalSessionVersion}`);
      return result;
    } catch (error) {
      this.logger.error('Error incrementing global session version:', error);
      throw new InternalServerErrorException('Failed to increment session version');
    }
  }


}
