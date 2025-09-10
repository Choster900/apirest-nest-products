import { BadRequestException, Injectable, InternalServerErrorException, Logger, UnauthorizedException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt'
import { LoginUserDto, CreateUserDto } from './dto';
import { JwtPayload } from './interfaces';

@Injectable()
export class AuthService {

    private readonly logger = new Logger('ProducsServices')

    constructor(
        @InjectRepository(User) readonly userRepository: Repository<User>,
        private readonly jwtService: JwtService
    ) { }

    async create(createUserDto: CreateUserDto) {
        try {

            const { password, ...userData } = createUserDto

            const user = this.userRepository.create({
                ...userData,
                password: bcrypt.hashSync(password, 10)
            })

            await this.userRepository.save(user)

            // Remove password from response
            const { password: _, ...userWithoutPassword } = user;

            return {
                ...userWithoutPassword,
                token: this.getJwtToken({ id: user.id })
            };

        } catch (error) {
            this.handleDbExecptions(error)
        }
    }


    async login(loginUserDto: LoginUserDto) {

        const { password, email } = loginUserDto

        const user = await this.userRepository.findOne({
            where: { email },
            select: {
                email: true,
                password: true,
                id: true,
                fullName: true,
                isActive: true,
                roles: true,
                biometricEnabled: true,
                deviceToken: true
            }
        })

        if (!user) {
            throw new UnauthorizedException('Credencials are not valid (email)')
        }

        if (!bcrypt.compareSync(password, user.password)) {
            throw new UnauthorizedException('Credentials are not valid ( password ) ')
        }

        // Remove password from response
        const { password: _, ...userWithoutPassword } = user;

        return {
            ...userWithoutPassword,
            token: this.getJwtToken({ id: user.id })
        };
    }

    private getJwtToken(payload: JwtPayload) {
        const token = this.jwtService.sign(payload);
        return token;
    }

    async checkAuthStatus(user: User) {
        return {
            ...user,
            token: this.getJwtToken({ id: user.id })
        };
    }

    private handleDbExecptions(error: any): never {
        if (error.code === '23505')
            throw new BadRequestException(error.detail)

        this.logger.error(error)

        throw new InternalServerErrorException('Error inesperado en el servidor')
    }
}
