import { Controller, Get, Post, Body, UseGuards, Headers, BadRequestException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginUserDto } from './dto';
import { Auth, GetUser } from './decorators';
import { User } from './entities/user.entity';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('register')
    create(@Body() createUserDto: CreateUserDto) {
        return this.authService.create(createUserDto);
    }

    @Post('login')
    loginUser(@Body() loginUserDto: LoginUserDto) {
        return this.authService.login(loginUserDto);
    }

    @Get('check-auth-status')
    @Auth()
    checkAuthStatus(
        @GetUser() user: User
    ) {
        return this.authService.checkAuthStatus(user);
    }

    @Get('check-status')
    verifyToken(@Headers('authorization') authHeader: string) {
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new BadRequestException('Authorization header with Bearer token is required');
        }

        const token = authHeader.substring(7); // Remove 'Bearer ' prefix
        return this.authService.verifyJwtToken(token);
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
