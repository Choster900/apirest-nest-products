import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { PushNotificationsService } from './push-notifications.service';
import { PushNotificationConfigService } from './config/push-notification-config.service';
import { NotificationsService } from './notifications.service';
import { PushNotificationsController } from './push-notifications.controller';

@Module({
  imports: [HttpModule],
  controllers: [PushNotificationsController],
  providers: [
    PushNotificationsService,
    NotificationsService,
    PushNotificationConfigService,
  ],
  exports: [
    PushNotificationsService,
    PushNotificationConfigService,
  ],
})
export class PushNotificationsModule { }
