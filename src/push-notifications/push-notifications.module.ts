import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { PushNotificationsService } from './push-notifications.service';
import { PushNotificationConfigService } from './config/push-notification-config.service';
import { NotificationsService } from './notifications.service';
import { PushNotificationsController } from './push-notifications.controller';
import { AuthService } from 'src/auth/auth.service';
import { AuthModule } from 'src/auth/auth.module';

@Module({
  imports: [HttpModule, AuthModule],
  controllers: [PushNotificationsController],
  providers: [
    PushNotificationsService,
    NotificationsService,
    PushNotificationConfigService,
    AuthService
  ],
  exports: [
    PushNotificationsService,
    PushNotificationConfigService,
    AuthService
  ],
})
export class PushNotificationsModule { }
