import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { PushNotificationsService } from './push-notifications.service';
import { PushNotificationsController } from './push-notifications.controller';
import { PushNotificationConfigService } from './config/push-notification-config.service';

@Module({
  imports: [HttpModule],
  controllers: [PushNotificationsController],
  providers: [
    PushNotificationsService,
    PushNotificationConfigService,
  ],
  exports: [
    PushNotificationsService,
    PushNotificationConfigService,
  ],
})
export class PushNotificationsModule {}
