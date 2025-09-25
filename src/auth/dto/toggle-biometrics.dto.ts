import { IsString, IsBoolean } from 'class-validator';

export class ToggleBiometricsDto {
    @IsString()
    deviceToken: string;

    @IsBoolean()
    enable: boolean;
}