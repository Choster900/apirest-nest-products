import { Controller, Get, Post, Body, UseGuards, Headers, BadRequestException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginUserDto, LoginDeviceTokenDto, SaveDeviceTokenDto, AllowMultipleSessionsDto, EnableBiometricsDto, DisableBiometricsDto } from './dto';
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
        // Validar que el header de autorización exista
        if (!authHeader) {
            throw new BadRequestException('Authorization header is required');
        }

        // Validar que tenga el formato correcto
        if (!authHeader.startsWith('Bearer ')) {
            throw new BadRequestException('Authorization header must start with "Bearer "');
        }

        // Extraer el token
        const token = authHeader.substring(7); // Remove 'Bearer ' prefix

        // Validar que el token no esté vacío después de remover el prefijo
        if (!token || token.trim().length === 0) {
            throw new BadRequestException('Token is required in Authorization header');
        }

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
    async enableBiometrics(@GetUser() user: User, @Body() enableBiometricsDto: EnableBiometricsDto) {
        return this.authService.enableBiometrics(user, enableBiometricsDto.deviceToken);
    }

    @Post('disable-biometrics')
    @Auth()
    async disableBiometrics(@GetUser() user: User, @Body() disableBiometricsDto: DisableBiometricsDto) {
        return this.authService.disableBiometrics(user.id, disableBiometricsDto.deviceToken);
    }

    @Post('login-with-device-token')
    async loginWithDeviceToken(@Body() loginDeviceTokenDto: LoginDeviceTokenDto) {
        return this.authService.loginWithDeviceToken(loginDeviceTokenDto.deviceToken);
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

    @Post('logout-all-devices')
    @Auth() // Requiere autenticación - puedes agregar validación de roles después
    async logoutAllDevices() {
        return this.authService.logoutAllDevices();
    }

    @Post('logout-user-devices')
    @Auth()
    async logoutUserDevices(@GetUser() user: User) {
        return this.authService.logoutAllDevicesForUser(user.id);
    }
}
