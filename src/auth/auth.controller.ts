import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginUserDto } from './dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }


    @Post('register')
    create(@Body() createUserDto: CreateUserDto) {

        try {
            return this.authService.create(createUserDto)
        } catch (error) {

        }
    }

    @Post('login')
    loginUser(@Body() loginUserDto: LoginUserDto) {

        try {
            return this.authService.login(loginUserDto)
        } catch (error) {

        }
    }

}
