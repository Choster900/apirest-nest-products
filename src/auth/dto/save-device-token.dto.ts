import { IsString, IsNotEmpty, IsUUID } from 'class-validator';

export class SaveDeviceTokenDto {
    @IsString()
    @IsNotEmpty()
    @IsUUID(4, { message: 'Device token must be a valid UUID v4' })
    deviceToken: string;
}
