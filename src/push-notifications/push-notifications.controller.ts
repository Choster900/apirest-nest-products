import { Body, Controller, Post } from '@nestjs/common';
import { PushNotificationsService } from './push-notifications.service';
import { CreateNotificationDto } from './dto/create-notification.dto';
import { CreatePushNotificationDto } from './dto/create-push-notification.dto';

@Controller('push-notifications')
export class PushNotificationsController {
  constructor(private readonly pushNotificationsService: PushNotificationsService) { }



  @Post('send')
  async send(@Body() body: CreatePushNotificationDto) {
    return this.pushNotificationsService.sendNotification(body);
  }
}
