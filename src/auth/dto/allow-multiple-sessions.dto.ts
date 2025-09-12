import { IsBoolean, IsOptional, IsString, IsUUID } from 'class-validator';

export class AllowMultipleSessionsDto {
    @IsBoolean()
    allow: boolean;

    @IsOptional()
    @IsString()
    @IsUUID('4', { message: 'Current device token must be a valid UUID v4' })
    currentDeviceToken?: string;
}
