import { Controller, Get, Post, Body, UseGuards, Headers, BadRequestException, NotFoundException, UnauthorizedException, Query, Res, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginUserDto, LoginDeviceTokenDto, SaveDeviceTokenDto, AllowMultipleSessionsDto, EnableBiometricsDto, DisableBiometricsDto, CheckMainDeviceDto } from './dto';
import { Auth, GetUser } from './decorators';
import { User } from './entities/user.entity';
import { PublicKeyGuard, CookieAuthGuard } from './guards';
import { Response, Request } from 'express';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService
    ) { }

    @Get('get-public-key')
    getPublicKey() {
        return this.authService.generatePublicToken();
    }

    @Post('register')
    @UseGuards(PublicKeyGuard)
    async create(@Body() createUserDto: CreateUserDto, @Res({ passthrough: true }) response: Response) {
        const result = await this.authService.create(createUserDto);
        
        // Establecer cookie HttpOnly segura (token seguro)
        this.setSecureCookie(response, result.token);
        
        // Devolver datos del usuario CON el token normal en la respuesta
        return {
            ...result,
            secureTokenSet: true // Indicador de que la cookie segura fue establecida
        };
    }

    @Post('login')
    @UseGuards(PublicKeyGuard)
    async loginUser(@Body() loginUserDto: LoginUserDto, @Res({ passthrough: true }) response: Response) {
        const result = await this.authService.login(loginUserDto);

        // Establecer cookie HttpOnly segura (token seguro)
        this.setSecureCookie(response, result.token);
        // Establecer refresh token en cookie HttpOnly
        this.setRefreshCookie(response, result.refreshToken);

        // Devolver datos del usuario CON ambos tokens en la respuesta
        return {
            ...result,
            secureTokenSet: true, // Indicador de que la cookie segura fue establecida
            refreshTokenSet: true // Indicador de que la cookie refresh fue establecida
        };
    }

    private setRefreshCookie(response: Response, refreshToken: string): void {
        response.cookie('secure_refresh_token', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 días
            path: '/'
        });
    }

    private setSecureCookie(response: Response, token: string): void {
        response.cookie('secure_token', token, {
            httpOnly: true,          // No accesible desde JavaScript
            secure: process.env.NODE_ENV === 'production', // Solo HTTPS en producción
            sameSite: 'strict',      // Protección CSRF
            maxAge: 24 * 60 * 60 * 1000, // 24 horas
            path: '/'               // Disponible en toda la app
        });
    }


    @Get('check-status')
    @UseGuards(CookieAuthGuard)
    verifyTokenFromCookie(@Req() request: Request, @Query('deviceToken') deviceToken?: string) {
        const tokenPayload = request['user'];
        const token = request['token'];
        
        return this.authService.verifyJwtToken(token, deviceToken);
    }

    @Get('profile')
    @UseGuards(CookieAuthGuard)
    getProfile(@Req() request: Request) {
        const tokenPayload = request['user'];
        
        if (!tokenPayload) {
            throw new UnauthorizedException('Token payload not found');
        }
        
        return {
            message: 'Profile accessed with secure cookie',
            user: {
                id: tokenPayload['id'] || tokenPayload['userId'],
                sessionVersion: tokenPayload['sessionVersion'] || 'unknown'
            }
        };
    }

    @Post('logout')
    @UseGuards(CookieAuthGuard)
    logout(@Res({ passthrough: true }) response: Response) {
        // Limpiar la cookie segura y la de refresh
        response.clearCookie('secure_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/'
        });
        response.clearCookie('secure_refresh_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/'
        });
        return {
            message: 'Logged out successfully',
            success: true
        };
    }

    @Get('check-auth-header')
    @UseGuards(PublicKeyGuard)
    checkAuthStatus(@Headers('authorization') authHeader: string, @Query('deviceToken') deviceToken?: string) {
        // Validar que el header de autorización esté presente
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

        return this.authService.verifyJwtToken(token, deviceToken);
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

    @Post('check-main-device')
    @Auth()
    async checkMainDevice(@GetUser() user: User, @Body() checkMainDeviceDto: CheckMainDeviceDto) {
        return this.authService.checkMainDevice(user, checkMainDeviceDto.deviceToken);
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
