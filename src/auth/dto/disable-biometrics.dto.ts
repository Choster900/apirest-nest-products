import { IsOptional, IsString, IsUUID } from 'class-validator';

export class DisableBiometricsDto {
    @IsOptional()
    @IsString()
    @IsUUID('4', { message: 'Device token must be a valid UUID v4' })
    deviceToken?: string;
}
