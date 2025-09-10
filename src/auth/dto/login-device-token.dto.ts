import { IsString, IsNotEmpty } from 'class-validator';

export class LoginDeviceTokenDto {
    @IsString()
    @IsNotEmpty()
    deviceToken: string;
}
