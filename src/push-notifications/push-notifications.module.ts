import { Module } from '@nestjs/common';
import { PushNotificationsService } from './push-notifications.service';
import { PushNotificationsController } from './push-notifications.controller';

@Module({
  controllers: [PushNotificationsController],
  providers: [PushNotificationsService],
})
export class PushNotificationsModule {}
