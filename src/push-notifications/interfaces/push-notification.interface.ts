/**
 * Interface for Expo push notification message structure
 */
export interface ExpoNotificationMessage {
    to: string;
    sound?: string | null;
    title: string;
    body: string;
    data?: Record<string, any>;
    priority?: 'default' | 'normal' | 'high';
    channelId?: string;
    badge?: number;
    ttl?: number;
}

/**
 * Interface for successful Expo push notification response
 */
export interface ExpoNotificationSuccessResponse {
    data: {
        status: 'ok';
        id: string;
    }
}

/**
 * Interface for failed Expo push notification response
 */
export interface ExpoNotificationErrorResponse {
    data: {
        status: 'error';
        message: string;
        details?: {
            error: 'DeviceNotRegistered' | 'InvalidCredentials' | 'MessageTooBig' | 'MessageRateExceeded' | string;
        };
    };
}

/**
 * Union type for Expo push notification response
 */
export type ExpoNotificationResponse = ExpoNotificationSuccessResponse | ExpoNotificationErrorResponse;

/**
 * Interface for standardized service response
 */
export interface PushNotificationResult {
    success: boolean;
    messageId?: string;
    error?: string;
    details?: any;
    timestamp: Date;
}

/**
 * Interface for batch notification results
 */
export interface BatchNotificationResult {
    totalSent: number;
    successCount: number;
    errorCount: number;
    results: PushNotificationResult[];
}

/**
 * Configuration interface for the push notification service
 */
export interface PushNotificationConfig {
    expoApiUrl: string;
    maxRetries: number;
    retryDelay: number;
    defaultTtl: number;
    defaultPriority: 'default' | 'normal' | 'high';
    defaultSound: string | null;
    defaultChannelId: string;
    timeout: number;
}