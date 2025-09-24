import { Injectable } from '@nestjs/common';
import { envs } from '../../config';
import { PushNotificationConfig } from '../interfaces/push-notification.interface';

/**
 * Configuration service for push notifications
 */
@Injectable()
export class PushNotificationConfigService {
    private readonly config: PushNotificationConfig;

    constructor() {
        this.config = {
            expoApiUrl: 'https://exp.host/--/api/v2/push/send',
            maxRetries: envs.PUSH_NOTIFICATION_MAX_RETRIES,
            retryDelay: envs.PUSH_NOTIFICATION_RETRY_DELAY,
            defaultTtl: 3600, // 1 hour
            defaultPriority: 'high',
            defaultSound: 'default',
            defaultChannelId: 'default',
            timeout: envs.PUSH_NOTIFICATION_TIMEOUT,
        };
    }

    /**
     * Get the complete configuration object
     */
    getConfig(): PushNotificationConfig {
        return { ...this.config };
    }

    /**
     * Get Expo API URL
     */
    getExpoApiUrl(): string {
        return this.config.expoApiUrl;
    }

    /**
     * Get maximum number of retries
     */
    getMaxRetries(): number {
        return this.config.maxRetries;
    }

    /**
     * Get retry delay in milliseconds
     */
    getRetryDelay(): number {
        return this.config.retryDelay;
    }

    /**
     * Get default TTL in seconds
     */
    getDefaultTtl(): number {
        return this.config.defaultTtl;
    }

    /**
     * Get default priority
     */
    getDefaultPriority(): 'default' | 'normal' | 'high' {
        return this.config.defaultPriority;
    }

    /**
     * Get default sound
     */
    getDefaultSound(): string | null {
        return this.config.defaultSound;
    }

    /**
     * Get default channel ID
     */
    getDefaultChannelId(): string {
        return this.config.defaultChannelId;
    }

    /**
     * Get timeout in milliseconds
     */
    getTimeout(): number {
        return this.config.timeout;
    }

    /**
     * Get headers for Expo API requests
     */
    getHeaders(): Record<string, string> {
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Accept-encoding': 'gzip, deflate',
        };

        // Add authorization header if Expo access token is provided
        if (envs.EXPO_ACCESS_TOKEN) {
            headers['Authorization'] = `Bearer ${envs.EXPO_ACCESS_TOKEN}`;
        }

        return headers;
    }
}