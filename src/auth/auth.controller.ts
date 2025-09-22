import { Controller, Get, Post, Body, UseGuards, Headers, BadRequestException, NotFoundException, UnauthorizedException, Query, Res, Req, Param } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bull';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginUserDto, LoginDeviceTokenDto, SaveDeviceTokenDto, AllowMultipleSessionsDto, EnableBiometricsDto, DisableBiometricsDto, ToggleBiometricsDto, RefreshTokenDto, CheckMainDeviceDto } from './dto';
import { Auth, GetUser } from './decorators';
import { User } from './entities/user.entity';
import { PublicKeyGuard, CookieAuthGuard, FlexibleAuthGuard, RefreshTokenGuard } from './guards';
import { Response, Request } from 'express';
import { v4 as uuid } from 'uuid';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        @InjectQueue('users') private usersQueue: Queue
    ) { }

    @Get('get-public-key')
    getPublicKey() {
        return this.authService.generatePublicToken();
    }

    @Post('register')
    @UseGuards(PublicKeyGuard)
    async create(@Body() createUserDto: CreateUserDto) {
        // Validación previa: verificar si el email ya existe
        const existingUser = await this.authService.findUserByEmailForValidation(createUserDto.email);
        if (existingUser) {
            throw new BadRequestException(`User with email ${createUserDto.email} already exists`);
        }

        // Generar ID único para el job
        const jobId = uuid();

        // Agregar el job a la cola
        const job = await this.usersQueue.add('register', {
            userData: createUserDto,
            jobId: jobId
        }, {
            // Configuraciones del job
            attempts: 3, // Reintentar hasta 3 veces si falla
            backoff: {
                type: 'exponential',
                delay: 2000, // 2 segundos inicial, luego 4s, 8s...
            },
            removeOnComplete: 10, // Mantener solo 10 jobs completados
            removeOnFail: 5, // Mantener solo 5 jobs fallidos
        });

        return {
            message: 'User registration queued successfully',
            jobId: jobId,
            status: 'queued',
            estimatedProcessingTime: '2-5 seconds',
            note: 'Check job status using /auth/job-status/:jobId endpoint'
        };
    }

    @Get('job-status/:jobId')
    @UseGuards(PublicKeyGuard)
    async getJobStatus(@Param('jobId') jobId: string) {
        try {
            // Buscar el job por ID
            const job = await this.usersQueue.getJob(jobId);

            if (!job) {
                throw new NotFoundException(`Job with ID ${jobId} not found`);
            }

            const state = await job.getState();
            const progress = job.progress();

            // Preparar respuesta base
            const response: any = {
                jobId,
                status: state,
                progress,
                createdAt: new Date(job.timestamp).toISOString(),
            };

            // Agregar información específica según el estado
            switch (state) {
                case 'completed':
                    response.result = job.returnvalue;
                    response.completedAt = job.finishedOn ? new Date(job.finishedOn).toISOString() : null;
                    response.success = true;
                    break;
                case 'failed':
                    response.error = job.failedReason;
                    response.failedAt = job.finishedOn ? new Date(job.finishedOn).toISOString() : null;
                    response.attempts = job.attemptsMade;
                    response.success = false;
                    response.statusCode = 400; // Indicar que es un error de cliente
                    break;
                case 'waiting':
                    response.message = 'Job is waiting to be processed';
                    response.success = null; // Aún no se sabe
                    break;
                case 'active':
                    response.message = 'Job is currently being processed';
                    response.startedAt = job.processedOn ? new Date(job.processedOn).toISOString() : null;
                    response.success = null; // Aún no se sabe
                    break;
                case 'delayed':
                    response.message = 'Job is delayed';
                    response.success = null; // Aún no se sabe
                    break;
            }

            return response;
        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            throw new BadRequestException(`Error checking job status: ${error.message}`);
        }
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
    @UseGuards(FlexibleAuthGuard)
    async verifyTokenFromCookie(@Req() request: Request, @Res({ passthrough: true }) response: Response, @Query('deviceToken') deviceToken?: string) {
        const tokenPayload = request['user'];
        const token = request['token'];

        const result = await this.authService.verifyJwtToken(token, deviceToken);

        // Actualizar cookies con los nuevos tokens generados
        this.setSecureCookie(response, result.token);
        this.setRefreshCookie(response, result.refreshToken);

        return {
            ...result,
            cookiesUpdated: true // Indicador de que las cookies fueron actualizadas
        };
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
    @UseGuards(FlexibleAuthGuard)
    async generateDeviceToken(@Req() request: Request) {
        // El guard ya validó el token y adjuntó la información del usuario
        const authResult = request['user'];
        return this.authService.generateDeviceToken();
    }

    @Post('refresh-token')
    @UseGuards(RefreshTokenGuard)
    async refreshToken(@Body() refreshTokenDto: RefreshTokenDto, @Req() request: Request, @Res({ passthrough: true }) response: Response) {
        // El guard ya validó el refresh token y adjuntó el payload
        const tokenPayload = request['user'];

        if (!tokenPayload || !tokenPayload['id']) {
            throw new UnauthorizedException('Invalid token payload');
        }

        const userId = tokenPayload['id'];

        // Generar nuevos tokens
        const result = await this.authService.refreshTokens(userId, refreshTokenDto.deviceToken);

        // Establecer nuevas cookies
        this.setSecureCookie(response, result.token);
        this.setRefreshCookie(response, result.refreshToken);

        // Devolver nuevos tokens
        return {
            ...result,
            message: 'Tokens refreshed successfully',
            secureTokenSet: true,
            refreshTokenSet: true
        };
    }

    @Post('save-device-token')
    @UseGuards(FlexibleAuthGuard)
    async saveDeviceToken(@GetUser() user: User, @Body() saveDeviceTokenDto: SaveDeviceTokenDto) {
        return this.authService.saveDeviceToken(user, saveDeviceTokenDto.deviceToken);
    }

    @Post('toggle-biometrics')
    @UseGuards(FlexibleAuthGuard)
    async toggleBiometrics(@GetUser() user: User, @Body() toggleBiometricsDto: ToggleBiometricsDto) {
        const { deviceToken, enable } = toggleBiometricsDto;

        if (enable) {
            return this.authService.enableBiometrics(user, deviceToken);
        } else {
            return this.authService.disableBiometrics(user.id, deviceToken);
        }
    }

    @Post('login-with-device-token')
    async loginWithDeviceToken(
        @Body() loginDeviceTokenDto: LoginDeviceTokenDto,
        @Res({ passthrough: true }) response: Response
    ) {
        const result = await this.authService.loginWithDeviceToken(loginDeviceTokenDto.deviceToken);
        this.setSecureCookie(response, result.token);
        this.setRefreshCookie(response, result.refreshToken);
        return {
            ...result,
            secureTokenSet: true,
            refreshTokenSet: true
        };
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
    @UseGuards(FlexibleAuthGuard)
    async checkMainDevice(@GetUser() user: User, @Body() checkMainDeviceDto: CheckMainDeviceDto) {
        return this.authService.checkMainDevice(user, checkMainDeviceDto.deviceToken);
    }

    @Post('set-main-device')
    @UseGuards(FlexibleAuthGuard)
    async setMainDevice(@GetUser() user: User, @Body() checkMainDeviceDto: CheckMainDeviceDto) {
        return this.authService.setMainDevice(user, checkMainDeviceDto.deviceToken);
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
