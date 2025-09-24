import { Injectable, Logger } from '@nestjs/common';
import fetch, { Response } from 'node-fetch';
import { CreatePushNotificationDto, NotificationPriority, NotificationSound } from './dto/create-push-notification.dto';
import { 
  ExpoNotificationMessage, 
  ExpoNotificationResponse, 
  PushNotificationResult, 
  BatchNotificationResult 
} from './interfaces/push-notification.interface';
import { PushNotificationConfigService } from './config/push-notification-config.service';
import { 
  PushNotificationException,
  DeviceNotRegisteredException,
  InvalidCredentialsException,
  MessageTooBigException,
  RateLimitExceededException,
  NetworkException
} from './exceptions/push-notification.exception';

/**
 * Service for sending push notifications via Expo Push Notification API
 * 
 * This service provides functionality to send push notifications to mobile devices
 * using the Expo Push Notification service. It includes proper error handling,
 * retry logic, validation, and logging.
 * 
 * @example
 * ```typescript
 * const result = await pushNotificationService.sendNotification({
 *   token: 'ExponentPushToken[xxxxx]',
 *   title: 'Hello',
 *   body: 'World',
 *   data: { userId: '123' }
 * });
 * ```
 */
@Injectable()
export class PushNotificationsService {
    private readonly logger = new Logger(PushNotificationsService.name);

    constructor(
        private readonly configService: PushNotificationConfigService
    ) {}

    /**
     * Send a single push notification
     * 
     * @param notificationDto - The notification data
     * @returns Promise with the notification result
     */
    async sendNotification(notificationDto: CreatePushNotificationDto): Promise<PushNotificationResult> {
        const startTime = Date.now();
        
        try {
            // Validate notification data
            this.validateNotificationData(notificationDto);

            // Build the message payload
            const message = this.buildNotificationMessage(notificationDto);

            // Send the notification with retry logic
            const response = await this.sendWithRetry(message);

            // Process the response
            const result = this.processResponse(response, startTime);

            this.logger.log(`Notification sent successfully to token: ${this.maskToken(notificationDto.token)}`, {
                messageId: result.messageId,
                duration: Date.now() - startTime,
            });

            return result;

        } catch (error) {
            this.logger.error(`Failed to send notification to token: ${this.maskToken(notificationDto.token)}`, {
                error: error.message,
                duration: Date.now() - startTime,
            });

            return {
                success: false,
                error: error.message,
                details: error.details || error,
                timestamp: new Date(),
            };
        }
    }

    /**
     * Send multiple push notifications in batch
     * 
     * @param notifications - Array of notification data
     * @returns Promise with batch results
     */
    async sendBatchNotifications(notifications: CreatePushNotificationDto[]): Promise<BatchNotificationResult> {
        const startTime = Date.now();
        
        this.logger.log(`Sending batch of ${notifications.length} notifications`);

        const results = await Promise.allSettled(
            notifications.map(notification => this.sendNotification(notification))
        );

        const processedResults: PushNotificationResult[] = results.map((result, index) => {
            if (result.status === 'fulfilled') {
                return result.value;
            } else {
                this.logger.error(`Batch notification ${index} failed: ${result.reason.message}`);
                return {
                    success: false,
                    error: result.reason.message,
                    timestamp: new Date(),
                };
            }
        });

        const successCount = processedResults.filter(r => r.success).length;
        const errorCount = processedResults.length - successCount;

        this.logger.log(`Batch completed: ${successCount} successful, ${errorCount} failed`, {
            duration: Date.now() - startTime,
        });

        return {
            totalSent: processedResults.length,
            successCount,
            errorCount,
            results: processedResults,
        };
    }

    /**
     * Validate notification data
     */
    private validateNotificationData(data: CreatePushNotificationDto): void {
        if (!data.token?.startsWith('ExponentPushToken[')) {
            throw new PushNotificationException('Invalid Expo push token format');
        }

        const messageSize = JSON.stringify(data).length;
        if (messageSize > 4096) {
            throw new MessageTooBigException(messageSize);
        }
    }

    /**
     * Build the notification message for Expo API
     */
    private buildNotificationMessage(dto: CreatePushNotificationDto): ExpoNotificationMessage {
        const config = this.configService.getConfig();
        
        return {
            to: dto.token,
            title: dto.title,
            body: dto.body,
            data: dto.data || {},
            priority: dto.priority || config.defaultPriority,
            sound: dto.sound === NotificationSound.NONE ? null : (dto.sound || config.defaultSound),
            channelId: dto.channelId || config.defaultChannelId,
            badge: dto.badge,
            ttl: dto.ttl || config.defaultTtl,
        };
    }

    /**
     * Send notification with retry logic
     */
    private async sendWithRetry(message: ExpoNotificationMessage, attempt = 1): Promise<ExpoNotificationResponse> {
        try {
            const response = await this.makeHttpRequest(message);
            return response;
        } catch (error) {
            const maxRetries = this.configService.getMaxRetries();
            
            if (attempt < maxRetries && this.isRetryableError(error)) {
                this.logger.warn(`Attempt ${attempt} failed, retrying...`, { error: error.message });
                
                await this.delay(this.configService.getRetryDelay() * attempt);
                return this.sendWithRetry(message, attempt + 1);
            }
            
            throw error;
        }
    }

    /**
     * Make HTTP request to Expo API
     */
    private async makeHttpRequest(message: ExpoNotificationMessage): Promise<ExpoNotificationResponse> {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.configService.getTimeout());

        try {
            const response: Response = await fetch(this.configService.getExpoApiUrl(), {
                method: 'POST',
                headers: this.configService.getHeaders(),
                body: JSON.stringify(message),
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new NetworkException(new Error(`HTTP ${response.status}: ${response.statusText}`));
            }

            const responseData = await response.json() as ExpoNotificationResponse;
            
            // Handle Expo API errors
            if (responseData.data.status === 'error') {
                this.handleExpoError(responseData);
            }

            return responseData;

        } catch (error) {
            clearTimeout(timeoutId);
            
            if (error.name === 'AbortError') {
                throw new NetworkException(new Error('Request timeout'));
            }
            
            if (error instanceof PushNotificationException) {
                throw error;
            }
            
            throw new NetworkException(error);
        }
    }

    /**
     * Handle Expo API specific errors
     */
    private handleExpoError(response: ExpoNotificationResponse): void {
        if (response.data.status !== 'error') return;

        const errorType = response.data.details?.error;

        switch (errorType) {
            case 'DeviceNotRegistered':
                throw new DeviceNotRegisteredException('Token not found');
            case 'InvalidCredentials':
                throw new InvalidCredentialsException();
            case 'MessageTooBig':
                throw new MessageTooBigException(0);
            case 'MessageRateExceeded':
                throw new RateLimitExceededException();
            default:
                throw new PushNotificationException(response.data.message);
        }
    }

    /**
     * Process the API response
     */
    private processResponse(response: ExpoNotificationResponse, startTime: number): PushNotificationResult {
        console.log(response)
        if (response.data.status === 'ok') {
            return {
                success: true,
                messageId: response.data.id,
                timestamp: new Date(),
            };
        }

        return {
            success: false,
            error: response.data.message,
            details: response.data.details,
            timestamp: new Date(),
        };
    }

    /**
     * Check if error is retryable
     */
    private isRetryableError(error: Error): boolean {
        // Retry on network errors, timeouts, and server errors
        return error instanceof NetworkException ||
               error.name === 'AbortError' ||
               error.message.includes('ECONNRESET') ||
               error.message.includes('ETIMEDOUT');
    }

    /**
     * Delay execution for retry logic
     */
    private async delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Mask token for logging (security)
     */
    private maskToken(token: string): string {
        if (!token || token.length < 10) return '[INVALID]';
        return `${token.substring(0, 20)}...${token.substring(token.length - 4)}`;
    }

    /**
     * Get service health status
     */
    async getHealthStatus(): Promise<{ status: 'healthy' | 'unhealthy', details: any }> {
        try {
            // Test with a dummy notification to check API availability
            const testMessage: ExpoNotificationMessage = {
                to: 'ExponentPushToken[test]',
                title: 'Health Check',
                body: 'Test message for health validation',
            };

            await fetch(this.configService.getExpoApiUrl(), {
                method: 'POST',
                headers: this.configService.getHeaders(),
                body: JSON.stringify(testMessage),
            });

            return {
                status: 'healthy',
                details: {
                    apiUrl: this.configService.getExpoApiUrl(),
                    timestamp: new Date().toISOString(),
                },
            };
        } catch (error) {
            return {
                status: 'unhealthy',
                details: {
                    error: error.message,
                    timestamp: new Date().toISOString(),
                },
            };
        }
    }
}
