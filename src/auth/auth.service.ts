import { BadRequestException, Injectable, InternalServerErrorException, Logger, UnauthorizedException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt'
import { LoginUserDto, CreateUserDto } from './dto';
import { JwtPayload } from './interfaces';
import { v4 as uuid } from 'uuid';

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

    async verifyJwtToken(token: string) {
        try {
            // Verificar y decodificar el token
            const payload = this.jwtService.verify(token);

            // Buscar el usuario en la base de datos
            const user = await this.userRepository.findOne({
                where: { id: payload.id },
                select: {
                    id: true,
                    email: true,
                    fullName: true,
                    isActive: true,
                    roles: true,
                    biometricEnabled: true,
                    deviceToken: true
                }
            });

            if (!user) {
                throw new UnauthorizedException('User not found');
            }

            if (!user.isActive) {
                throw new UnauthorizedException('User is inactive, talk with an admin');
            }

            return {
                ...user,
                token: this.getJwtToken({ id: user.id })
            };

        } catch (error) {
            if (error.name === 'JsonWebTokenError') {
                throw new UnauthorizedException('Invalid token');
            }
            if (error.name === 'TokenExpiredError') {
                throw new UnauthorizedException('Token has expired');
            }
            throw error;
        }
    }

    async enableBiometrics(user: User) {
        try {
            // Validar si la biometría ya está habilitada
            if (user.biometricEnabled && user.deviceToken) {
                return {
                    deviceToken: user.deviceToken,
                    message: 'Biometrics already enabled for this user'
                };
            }

            const deviceToken = uuid(); // Genera token aleatorio único

            user.deviceToken = deviceToken;
            user.biometricEnabled = true;

            await this.userRepository.save(user);

            return {
                deviceToken,
                message: 'Biometrics enabled successfully'
            };

        } catch (error) {
            this.handleDbExecptions(error);
        }
    }

    async loginWithDeviceToken(deviceToken: string) {
        try {
            const user = await this.userRepository.findOne({
                where: { deviceToken },
                select: {
                    id: true,
                    email: true,
                    fullName: true,
                    isActive: true,
                    roles: true,
                    biometricEnabled: true,
                    deviceToken: true
                }
            });

            if (!user) {
                throw new UnauthorizedException('Invalid device token');
            }

            if (!user.isActive) {
                throw new UnauthorizedException('User is inactive, talk with an admin');
            }

            if (!user.biometricEnabled) {
                throw new UnauthorizedException('Biometrics not enabled for this user');
            }

            return {
                ...user,
                token: this.getJwtToken({ id: user.id })
            };

        } catch (error) {
            if (error instanceof UnauthorizedException) {
                throw error;
            }
            this.handleDbExecptions(error);
        }
    }

    private handleDbExecptions(error: any): never {
        if (error.code === '23505')
            throw new BadRequestException(error.detail)

        this.logger.error(error)

        throw new InternalServerErrorException('Error inesperado en el servidor')
    }
}
