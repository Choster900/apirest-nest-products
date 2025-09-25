import { Body, Controller, Post } from '@nestjs/common';
import { PushNotificationsService } from './push-notifications.service';
import { CreateNotificationDto } from './dto/create-notification.dto';
import { CreatePushNotificationDto } from './dto/create-push-notification.dto';
import { NotificationsService } from './notifications.service';

@Controller('push-notifications')
export class PushNotificationsController {
  constructor(
    private readonly pushNotificationsService: PushNotificationsService,
    private readonly notificationsService: NotificationsService,
  ) { }



  @Post('send')
  async send(@Body() body: CreatePushNotificationDto) {
    return this.pushNotificationsService.sendNotification(body);
  }

  @Post('send-batch')
  async sendBatch(@Body() body: CreatePushNotificationDto[]) {
    return this.pushNotificationsService.sendBatchNotifications(body);
  }

  @Post('send-v2')
  async sendv2(@Body() body: CreateNotificationDto) {
    return this.notificationsService.sendNotification(body);
  }

  //send-v2-by-user
  @Post('send-v2-by-user')
  async sendv2ByUser(@Body() body: { userId: string; title: string; message: string; data?: Record<string, string> }) {
    return this.notificationsService.sendNotificationByUser(body);
  }
}
