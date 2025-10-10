// src/notifications/notifications.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { CreateNotificationDto } from './dto/create-notification.dto';
import admin from 'src/common/firebase';
import { AuthService } from 'src/auth/auth.service';
import { User } from 'src/auth/entities/user.entity';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class NotificationsService {
    constructor(
        private readonly authService: AuthService,
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
    ) { }

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

    async sendNotificationByUser(
        { userId, title, message, data }: { userId: string; title: string; message: string; data?: Record<string, string> }
    ) {
        if (!userId/*  || !title || !message */) {
            throw new Error('Faltan datos para enviar la notificación');
        }
        // Aquí deberías implementar la lógica para obtener el token del usuario desde tu base de datos
        const user = await this.userRepository.findOne({ where: { id: userId }, relations: ['sessions'] });
        if (!user) {
            throw new Error('Usuario no encontrado');
        }

        const fcmToken = user.sessions.filter(session => session.pushActive);

        if (!fcmToken || fcmToken.length === 0) {
            throw new Error('El usuario no tiene un token de dispositivo válido');
        }

        fcmToken.map(session => {
            this.sendNotification({
                token: session.pushToken || '',
                title: title || 'Notificación',
                message : message || 'Tienes una nueva notificación',
                data
            });

        });

        return true;
    }
}