import { HttpException, HttpStatus } from '@nestjs/common';

/**
 * Custom exception for push notification errors
 */
export class PushNotificationException extends HttpException {
    constructor(
        message: string,
        status: HttpStatus = HttpStatus.BAD_REQUEST,
        public readonly details?: any
    ) {
        super(
            {
                message,
                error: 'Push Notification Error',
                statusCode: status,
                details,
                timestamp: new Date().toISOString(),
            },
            status
        );
    }
}

/**
 * Exception for device registration errors
 */
export class DeviceNotRegisteredException extends PushNotificationException {
    constructor(token: string) {
        super(
            `Device with token ${token} is not registered`,
            HttpStatus.BAD_REQUEST,
            { token, errorType: 'DEVICE_NOT_REGISTERED' }
        );
    }
}

/**
 * Exception for invalid credentials
 */
export class InvalidCredentialsException extends PushNotificationException {
    constructor() {
        super(
            'Invalid credentials for push notification service',
            HttpStatus.UNAUTHORIZED,
            { errorType: 'INVALID_CREDENTIALS' }
        );
    }
}

/**
 * Exception for message too big
 */
export class MessageTooBigException extends PushNotificationException {
    constructor(messageSize: number, maxSize: number = 4096) {
        super(
            `Message size (${messageSize} bytes) exceeds the maximum allowed size (${maxSize} bytes)`,
            HttpStatus.BAD_REQUEST,
            { messageSize, maxSize, errorType: 'MESSAGE_TOO_BIG' }
        );
    }
}

/**
 * Exception for rate limit exceeded
 */
export class RateLimitExceededException extends PushNotificationException {
    constructor() {
        super(
            'Message rate limit exceeded. Please try again later',
            HttpStatus.TOO_MANY_REQUESTS,
            { errorType: 'RATE_LIMIT_EXCEEDED' }
        );
    }
}

/**
 * Exception for network or timeout errors
 */
export class NetworkException extends PushNotificationException {
    constructor(originalError?: Error) {
        super(
            'Network error occurred while sending push notification',
            HttpStatus.SERVICE_UNAVAILABLE,
            { errorType: 'NETWORK_ERROR', originalError: originalError?.message }
        );
    }
}