// src/notifications/notifications.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { CreateNotificationDto } from './dto/create-notification.dto';
import admin from 'src/common/firebase';

@Injectable()
export class NotificationsService {
    private readonly logger = new Logger(NotificationsService.name);

    async sendNotification(
        { token, title, message, data }: CreateNotificationDto
    ) {
        if (!token || !title || !message) {
            throw new Error('Faltan datos para enviar la notificación');
        }

        const messagePayload = {
            token,
            notification: { title, body: message },
            android: {
                notification: {
                    sound: 'default', // activa el sonido
                    channelId: 'default', // debe coincidir con tu canal en Android
                    
                },
            },
            apns: {
                payload: {
                    aps: {
                        sound: 'default', // para iOS
                    },
                },
            },
            data: data || {},
        };

        try {
            const response = await admin.messaging().send(messagePayload);
            return response;
        } catch (error) {
            this.logger.error('Error al enviar la notificación', error.stack);
            throw error;
        }
    }
}
