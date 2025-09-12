import { IsString, IsUUID } from 'class-validator';

export class EnableBiometricsDto {
    @IsString()
    @IsUUID('4', { message: 'Device token must be a valid UUID v4' })
    deviceToken: string;
}
