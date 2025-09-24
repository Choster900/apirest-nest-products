import { Injectable, Logger } from '@nestjs/common';
import fetch from 'node-fetch';

@Injectable()
export class PushNotificationsService {
    private readonly logger = new Logger(PushNotificationsService.name);

    async sendNotification(token: string, title: string, body: string, data?: any) {
        const message = {
            to: token, // ExponentPushToken[xxxx...]
            sound: 'default', // Puedes cambiar a 'default' o quitarlo si no deseas sonido
            title,
            body,
            data: data || {},
            priority: 'high', // Opcional: 'default' | 'normal' | 'high'
            channelId: 'default', // Opcional: para Android, especifica el canal de notificación
            badge: 2, // Opcional: número de badge para iOS
            ttl: 60, // Opcional: tiempo de vida del mensaje en segundos
        };

        try {
            const response = await fetch('https://exp.host/--/api/v2/push/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(message),
            });

            const resJson = await response.json();
            this.logger.log('Notificación enviada', resJson);
            return resJson;
        } catch (error) {
            this.logger.error('Error al enviar notificación', error);
            throw error;
        }
    }
}
