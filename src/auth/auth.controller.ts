import { Controller, Get, Post, Body, UseGuards, Headers, BadRequestException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginUserDto, LoginDeviceTokenDto, SaveDeviceTokenDto } from './dto';
import { Auth, GetUser } from './decorators';
import { User } from './entities/user.entity';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService
    ) { }

    @Post('register')
    create(@Body() createUserDto: CreateUserDto) {
        return this.authService.create(createUserDto);
    }

    @Post('login')
    loginUser(@Body() loginUserDto: LoginUserDto) {
        return this.authService.login(loginUserDto);
    }


    @Get('check-status')
    verifyToken(@Headers('authorization') authHeader: string) {
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new BadRequestException('Authorization header with Bearer token is required');
        }

        const token = authHeader.substring(7); // Remove 'Bearer ' prefix
        return this.authService.verifyJwtToken(token);
    }


    @Post('generate-device-token')
    @Auth()
    async generateDeviceToken() {
        return this.authService.generateDeviceToken();
    }

    @Post('save-device-token')
    @Auth()
    async saveDeviceToken(@GetUser() user: User, @Body() saveDeviceTokenDto: SaveDeviceTokenDto) {
        return this.authService.saveDeviceToken(user, saveDeviceTokenDto.deviceToken);
    }

    @Post('enable-biometrics')
    @Auth()
    async enableBiometrics(@GetUser() user: User) {
        return this.authService.enableBiometrics(user);
    }

    @Post('disable-biometrics')
    @Auth()
    async disableBiometrics(@GetUser() user: User) {
        await this.authService.disableBiometrics(user.id);
        return {
            message: 'Biometrics disabled successfully'
        };
    }

    @Post('login-with-device-token')
    async loginWithDeviceToken(@Body() loginDeviceTokenDto: LoginDeviceTokenDto) {
        return this.authService.loginWithDeviceToken(loginDeviceTokenDto.deviceToken);
    }

    @Post('allow-multiple-sessions')
    @Auth()
    async allowMultipleSessions(@GetUser() user: User, @Body('allow') allow: boolean) {
        return this.authService.allowMultipleSessions(user.id, allow);
    }

    @Get('private')
    @Auth()
    testingPrivateRoute(
        @GetUser() user: User,
        @GetUser('email') userEmail: string,
    ) {
        return {
            ok: true,
            message: 'Hola mundo privado',
            user,
            userEmail,
        }
    }
}
