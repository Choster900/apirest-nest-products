import { BadRequestException, Injectable, InternalServerErrorException, Logger, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { Session } from './entities/sessions.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt'
import { LoginUserDto, CreateUserDto } from './dto';
import { JwtPayload, DeviceTokenInfo } from './interfaces';
import { v4 as uuid } from 'uuid';

@Injectable()
export class AuthService {

    private readonly logger = new Logger('ProducsServices')

    constructor(
        @InjectRepository(User) readonly userRepository: Repository<User>,
        @InjectRepository(Session) readonly sessionRepository: Repository<Session>,
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
            relations: ['sessions'],
            select: {
                email: true,
                password: true,
                id: true,
                fullName: true,
                isActive: true,
                roles: true,
                biometricEnabled: true,
                allowMultipleSessions: true
            }
        })

        if (!user) {
            throw new UnauthorizedException('Credencials are not valid (email)')
        }

        if (!bcrypt.compareSync(password, user.password)) {
            throw new UnauthorizedException('Credentials are not valid ( password ) ')
        }

        // Obtener todos los device tokens con su estado
        const deviceTokens = await this.getAllDeviceTokens(user.id);

        // Obtener solo los tokens activos para compatibilidad
        const activeDeviceTokens = deviceTokens
            .filter(token => token.isActive)
            .map(token => token.deviceToken);

        // Remove password from response
        const { password: _, sessions, ...userWithoutPassword } = user;

        return {
            ...userWithoutPassword,
            activeDeviceTokens, // Para compatibilidad con código existente
            deviceTokens, // Nuevo campo con todos los tokens y su estado
            token: this.getJwtToken({ id: user.id })
        };
    }

    private getJwtToken(payload: JwtPayload) {
        const token = this.jwtService.sign(payload);
        return token;
    }

    private async getActiveDeviceTokens(userId: string): Promise<string[]> {
        const activeSessions = await this.sessionRepository.find({
            where: {
                userId,
                isActive: true
            },
            select: ['deviceToken']
        });

        return activeSessions
            .map(session => session.deviceToken)
            .filter((token): token is string => token !== null);
    }

    private async getAllDeviceTokens(userId: string): Promise<DeviceTokenInfo[]> {
        const sessions = await this.sessionRepository.find({
            where: { userId },
            select: ['id', 'deviceToken', 'isActive']
        });

        return sessions
            .filter(session => session.deviceToken)
            .map(session => ({
                deviceToken: session.deviceToken!,
                isActive: session.isActive,
                sessionId: session.id
            }));
    }

    async verifyJwtToken(token: string) {
        try {
            // Verificar y decodificar el token
            const payload = this.jwtService.verify(token);

            // Buscar el usuario en la base de datos
            const user = await this.userRepository.findOne({
                where: { id: payload.id },
                relations: ['sessions'],
                select: {
                    id: true,
                    email: true,
                    fullName: true,
                    isActive: true,
                    roles: true,
                    biometricEnabled: true,
                    allowMultipleSessions: true
                }
            });

            if (!user) {
                throw new UnauthorizedException('User not found');
            }

            if (!user.isActive) {
                throw new UnauthorizedException('User is inactive, talk with an admin');
            }

            const activeDeviceTokens = await this.getActiveDeviceTokens(user.id);
            const deviceTokens = await this.getAllDeviceTokens(user.id);

            return {
                ...user,
                token: this.getJwtToken({ id: user.id }),
                activeDeviceTokens,
                deviceTokens
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
            const existingSession = await this.sessionRepository.findOne({
                where: { deviceToken, isActive: true }
            });

            if (existingSession && existingSession.userId !== user.id) {
                throw new BadRequestException('This device token is already in use by another account');
            }

            // Si no permite múltiples sesiones, desactivar sesiones existentes
            if (!user.allowMultipleSessions) {
                await this.sessionRepository.update(
                    { userId: user.id, isActive: true },
                    { isActive: false }
                );
            }

            // Crear o actualizar la sesión
            let session = await this.sessionRepository.findOne({
                where: { userId: user.id, deviceToken }
            });

            if (!session) {
                session = this.sessionRepository.create({
                    userId: user.id,
                    deviceToken,
                    isActive: true
                });
            } else {
                session.isActive = true;
            }

            await this.sessionRepository.save(session);

            // Habilitar biometría al guardar el token por primera vez
            user.biometricEnabled = true;
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
            const activeDeviceTokens = await this.getActiveDeviceTokens(user.id);

            if (activeDeviceTokens.length === 0) {
                throw new BadRequestException('You must save a device token first before enabling biometrics. Use /generate-device-token and then /save-device-token');
            }

            user.biometricEnabled = true;

            await this.userRepository.save(user);

            return {
                activeDeviceTokens,
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

            // Desactivar todas las sesiones del usuario
            await this.sessionRepository.update(
                { userId, isActive: true },
                { isActive: false }
            );

            await this.userRepository.save(user);

        } catch (error) {
            this.handleDbExecptions(error);
        }
    }

    async loginWithDeviceToken(deviceToken: string) {
        try {
            // Buscar sesión activa con el device token
            const session = await this.sessionRepository.findOne({
                where: { deviceToken, isActive: true },
                relations: ['user']
            });

            if (!session || !session.user) {
                throw new UnauthorizedException('Invalid device token');
            }

            const user = session.user;

            if (!user.isActive) {
                throw new UnauthorizedException('User is inactive, talk with an admin');
            }

            if (!user.biometricEnabled) {
                throw new UnauthorizedException('Biometrics not enabled for this user');
            }

            const activeDeviceTokens = await this.getActiveDeviceTokens(user.id);
            const deviceTokens = await this.getAllDeviceTokens(user.id);

            return {
                id: user.id,
                email: user.email,
                fullName: user.fullName,
                isActive: user.isActive,
                roles: user.roles,
                biometricEnabled: user.biometricEnabled,
                allowMultipleSessions: user.allowMultipleSessions,
                activeDeviceTokens,
                deviceTokens,
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
