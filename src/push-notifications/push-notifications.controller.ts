import { Body, Controller, Post } from '@nestjs/common';
import { PushNotificationsService } from './push-notifications.service';
import { CreateNotificationDto } from './dto/create-notification.dto';

@Controller('push-notifications')
export class PushNotificationsController {
  constructor(private readonly pushNotificationsService: PushNotificationsService) { }



  @Post('send')
  async send(@Body() body: CreateNotificationDto) {
    return this.pushNotificationsService.sendNotification(body.token, body.title, body.message, body.data);
  }
}
