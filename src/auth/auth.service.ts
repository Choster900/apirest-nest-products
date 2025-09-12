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
            select: ['id', 'deviceToken', 'isActive', 'biometricEnabled']
        });

        return sessions
            .filter(session => session.deviceToken)
            .map(session => ({
                deviceToken: session.deviceToken!,
                isActive: session.isActive,
                sessionId: session.id,
                biometricEnabled: session.biometricEnabled
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

            // Habilitar biometría al guardar el token por primera vez
            session.biometricEnabled = true;
            await this.sessionRepository.save(session);

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

    async enableBiometrics(user: User, deviceToken: string) {
        try {
            // Buscar la sesión específica por device token
            const session = await this.sessionRepository.findOne({
                where: {
                    userId: user.id,
                    deviceToken: deviceToken
                }
            });

            if (!session) {
                throw new NotFoundException('Device token not found for this user. Make sure the device token is registered.');
            }

            if (!session.isActive) {
                throw new BadRequestException('The specified device session is inactive. Please activate the session first.');
            }

            // Validar si la biometría ya está habilitada para este dispositivo
            if (session.biometricEnabled) {
                return {
                    message: 'Biometrics already enabled for this device',
                    deviceToken: session.deviceToken,
                    sessionId: session.id,
                    biometricEnabled: session.biometricEnabled
                };
            }

            // Habilitar biometría para esta sesión específica
            session.biometricEnabled = true;
            await this.sessionRepository.save(session);

            return {
                deviceToken: session.deviceToken,
                sessionId: session.id,
                biometricEnabled: session.biometricEnabled,
                message: 'Biometrics enabled successfully for the specified device'
            };

        } catch (error) {
            if (error instanceof BadRequestException || error instanceof NotFoundException) {
                throw error;
            }
            this.handleDbExecptions(error);
        }
    }

    async disableBiometrics(userId: string, deviceToken?: string) {
        try {
            const user = await this.userRepository.findOneBy({ id: userId });
            if (!user) throw new NotFoundException('User not found');

            if (deviceToken) {
                // Deshabilitar biometría para un dispositivo específico
                const session = await this.sessionRepository.findOne({
                    where: { userId, deviceToken }
                });

                if (!session) {
                    throw new NotFoundException('Device token not found for this user');
                }

                session.biometricEnabled = false;
                await this.sessionRepository.save(session);

                return {
                    message: 'Biometrics disabled successfully for the specified device',
                    deviceToken: session.deviceToken,
                    sessionId: session.id
                };
            } else {
                // Deshabilitar biometría para todas las sesiones
                await this.sessionRepository.update(
                    { userId },
                    { biometricEnabled: false }
                );

                // También desactivar todas las sesiones del usuario
                await this.sessionRepository.update(
                    { userId, isActive: true },
                    { isActive: false }
                );

                return {
                    message: 'Biometrics disabled successfully for all devices'
                };
            }

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

            if (!session.biometricEnabled) {
                throw new UnauthorizedException('Biometrics not enabled for this device');
            }

            const activeDeviceTokens = await this.getActiveDeviceTokens(user.id);
            const deviceTokens = await this.getAllDeviceTokens(user.id);

            return {
                id: user.id,
                email: user.email,
                fullName: user.fullName,
                isActive: user.isActive,
                roles: user.roles,
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


    async allowMultipleSessions(userId: string, allow: boolean, currentDeviceToken?: string) {
        try {
            const user = await this.userRepository.findOneBy({ id: userId });
            if (!user) throw new NotFoundException('User not found');

            user.allowMultipleSessions = allow;
            await this.userRepository.save(user);

            // Si allow es false, desactivar todas las sesiones excepto la actual
            if (!allow && currentDeviceToken) {
                // Desactivar todas las sesiones activas excepto la del dispositivo actual
                await this.sessionRepository.createQueryBuilder()
                    .update()
                    .set({ isActive: false })
                    .where("userId = :userId", { userId })
                    .andWhere("deviceToken != :currentDeviceToken", { currentDeviceToken })
                    .andWhere("isActive = :isActive", { isActive: true })
                    .execute();

                // Obtener información actualizada de tokens
                const deviceTokens = await this.getAllDeviceTokens(userId);
                const activeDeviceTokens = await this.getActiveDeviceTokens(userId);

                return {
                    message: `Multiple sessions disabled successfully. All other sessions have been deactivated.`,
                    activeDeviceTokens,
                    deviceTokens
                };
            } else if (!allow && !currentDeviceToken) {
                // Si no se proporciona currentDeviceToken, desactivar todas las sesiones
               /*  await this.sessionRepository.update(
                    { userId, isActive: true },
                    { isActive: false }
                ); */

                return {
                    message: `Multiple sessions disabled successfully. All sessions have been deactivated.`,
                    activeDeviceTokens: [],
                    deviceTokens: await this.getAllDeviceTokens(userId)
                };
            }

            // Si allow es true, solo actualizar la configuración
            const deviceTokens = await this.getAllDeviceTokens(userId);
            const activeDeviceTokens = await this.getActiveDeviceTokens(userId);

            return {
                message: `Multiple sessions ${allow ? 'enabled' : 'disabled'} successfully.`,
                activeDeviceTokens,
                deviceTokens
            };
        } catch (error) {
            this.handleDbExecptions(error);
        }
    }
}
