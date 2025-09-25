import { IsString, IsNotEmpty, MaxLength, IsOptional, IsObject, IsEnum, IsNumber, Min, Max } from 'class-validator';

/**
 * Enum for notification priority levels
 */
export enum NotificationPriority {
    DEFAULT = 'default',
    NORMAL = 'normal',
    HIGH = 'high',
}

/**
 * Enum for sound options
 */
export enum NotificationSound {
    DEFAULT = 'default',
    NONE = 'none',
}

/**
 * DTO for creating a push notification
 */
export class CreatePushNotificationDto {
    @IsString()
    @IsNotEmpty()
    @MaxLength(255)
    token: string;

    @IsString()
    @IsNotEmpty()
    @MaxLength(100)
    title: string;

    @IsString()
    @IsNotEmpty()
    @MaxLength(255)
    body: string;

    @IsOptional()
    @IsObject()
    data?: Record<string, any>;

    @IsOptional()
    @IsEnum(NotificationPriority)
    priority?: NotificationPriority;

    @IsOptional()
    @IsEnum(NotificationSound)
    sound?: NotificationSound;

    @IsOptional()
    @IsString()
    channelId?: string;

    @IsOptional()
    @IsNumber()
    @Min(0)
    @Max(99)
    badge?: number;

    @IsOptional()
    @IsNumber()
    @Min(0)
    @Max(2419200)
    ttl?: number;
}