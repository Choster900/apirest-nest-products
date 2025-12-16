import { Module } from '@nestjs/common';
import { SeedService } from './seed.service';
import { SeedController } from './seed.controller';
import { AppSettingsModule } from 'src/app-settings/app-settings.module';

@Module({
  controllers: [SeedController],
  providers: [SeedService],
  imports: [AppSettingsModule]
})
export class SeedModule {}
