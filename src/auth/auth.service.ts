import { BadRequestException, Injectable, InternalServerErrorException, Logger, NotFoundException, UnauthorizedException } from '@nestjs/common';
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
                deviceToken: true,
                allowMultipleSessions: true
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
                    deviceToken: true,
                    allowMultipleSessions: true
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

    async generateDeviceToken() {
        try {
            // Solo genera un token único sin guardarlo
            const deviceToken = uuid();

            return {
                deviceToken,
                message: 'Device token generated successfully',
                note: 'This token must be saved using /save-device-token endpoint'
            };

        } catch (error) {
            this.handleDbExecptions(error);
        }
    }

    async saveDeviceToken(user: User, deviceToken: string) {
        try {

            // Verificar que el token no esté siendo usado por otro usuario
            const existingUser = await this.userRepository.findOne({
                where: { deviceToken }
            });

            if (existingUser) {
                throw new BadRequestException('This device token is already in use by another account');
            }

            // Guardar el token
            user.deviceToken = deviceToken;
            user.biometricEnabled = true; // Habilitar biometría al guardar el token por primera vez
            await this.userRepository.save(user);

            return {
                deviceToken,
                message: 'Device token saved successfully',
                deviceStatus: 'registered'
            };

        } catch (error) {
            if (error instanceof BadRequestException) {
                throw error;
            }
            this.handleDbExecptions(error);
        }
    }

    async enableBiometrics(user: User) {
        try {
            // Validar si la biometría ya está habilitada
            if (user.biometricEnabled) {
                return {
                    message: 'Biometrics already enabled for this user'
                };
            }

            // Validar que haya un dispositivo registrado primero
            if (!user.deviceToken) {
                throw new BadRequestException('You must save a device token first before enabling biometrics. Use /generate-device-token and then /save-device-token');
            }

            user.biometricEnabled = true;
            // No modificamos el deviceToken, solo habilitamos biometría

            await this.userRepository.save(user);

            return {
                deviceToken: user.deviceToken,
                message: 'Biometrics enabled successfully'
            };

        } catch (error) {
            if (error instanceof BadRequestException) {
                throw error;
            }
            this.handleDbExecptions(error);
        }
    }

    async disableBiometrics(userId: string) {
        try {
            const user = await this.userRepository.findOneBy({ id: userId });
            if (!user) throw new NotFoundException('User not found');
            user.biometricEnabled = false;
            user.deviceToken = null;

            await this.userRepository.save(user);

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


    async allowMultipleSessions(userId: string, allow: boolean) {
        try {
            const user = await this.userRepository.findOneBy({ id: userId });
            if (!user) throw new NotFoundException('User not found');
            user.allowMultipleSessions = allow;
            await this.userRepository.save(user);
            return {
                message: `Multiple sessions ${allow ? 'enabled' : 'disabled'} successfully.`
            };
        } catch (error) {
            this.handleDbExecptions(error);
        }
    }
}
