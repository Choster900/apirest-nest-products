import { IsNotEmpty, IsString } from 'class-validator';

export class CheckMainDeviceDto {
    @IsString()
    @IsNotEmpty()
    deviceToken: string;
}