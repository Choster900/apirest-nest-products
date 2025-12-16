import {
    BadRequestException,
    ForbiddenException,
    Injectable,
    InternalServerErrorException,
    Logger,
    NotFoundException,
    UnauthorizedException
} from '@nestjs/common';
import { Repository, Not } from 'typeorm';
import { User } from './entities/user.entity';
import { Session } from './entities/sessions.entity';
import { AppSettings } from '../app-settings/entities/app-settings.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { LoginUserDto, CreateUserDto } from './dto';
import {
    JwtPayload,
    DeviceTokenInfo,
    AuthResponse,
    FoundDeviceTokenInfo,
    DeviceTokenResponse,
    LogoutResponse,
    BiometricResponse,
    MainDeviceResponse
} from './interfaces';
import { v4 as uuid } from 'uuid';
import { envs } from '../config';
@Injectable()
export class AuthService {
    private readonly logger = new Logger('AuthService');
    private readonly SALT_ROUNDS = 10;
    private readonly DEFAULT_SETTINGS_ID = 1;

    constructor(
        @InjectRepository(User)
        private readonly userRepository: Repository<User>,
        @InjectRepository(Session)
        private readonly sessionRepository: Repository<Session>,
        @InjectRepository(AppSettings)
        private readonly appSettingsRepository: Repository<AppSettings>,
        private readonly jwtService: JwtService
    ) { }

    async findUserByEmailOrIdForValidation(identifier: string): Promise<User | null> {
        const isEmail = identifier.includes('@');
        
        if (isEmail) {
            return await this.userRepository.findOne({
                where: { email: identifier },
                select: ['id', 'email']
            });
        } else {
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            
            if (uuidRegex.test(identifier)) {
                return await this.userRepository.findOne({
                    where: { id: identifier },
                    select: ['id', 'email']
                });
            }
            return null;
        }
    }

    async generatePublicToken(): Promise<{ token: string; expiresIn: string }> {
        const payload = {
            isPublicKey: true,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60)
        };

        const token = this.jwtService.sign(payload, {
            secret: envs.JWT_PUBLIC_SECRET
        });

        return {
            token,
            expiresIn: '365d'
        };
    }

    async refreshTokens(userId: string, deviceToken?: string): Promise<AuthResponse> {
        const user = await this.findUserById(userId);
        this.validateUserStatus(user);
        const appSettings = await this.getAppSettings();
        const foundDeviceToken = await this.getFoundDeviceToken(user.id, deviceToken);
        return this.buildAuthResponse(user, foundDeviceToken);
    }

    async create(createUserDto: CreateUserDto): Promise<AuthResponse> {
        try {
            const { password, ...userData } = createUserDto;

            const hashedPassword = bcrypt.hashSync(password, this.SALT_ROUNDS);
            const user = this.userRepository.create({
                ...userData,
                password: hashedPassword
            });

            await this.userRepository.save(user);

            return this.buildAuthResponse(user, null);
        } catch (error) {
            this.handleDbExceptions(error);
        }
    }

    async login(loginUserDto: LoginUserDto): Promise<AuthResponse> {
        const { password, email, deviceToken } = loginUserDto;
        const user = await this.findUserByEmail(email);
        const isValid = await this.validateUser(user, password);
        if (!isValid) {
            throw new UnauthorizedException('Invalid credentials');
        }
        const foundDeviceToken = await this.getFoundDeviceToken(user.id, deviceToken);

        return this.buildAuthResponse(user, foundDeviceToken);
    }

    async verifyJwtToken(token: string, deviceToken?: string): Promise<AuthResponse> {
        try {
            this.validateTokenFormat(token);
            const payload = this.decodeAndValidateToken(token);
            const user = await this.findUserById(payload.id);

            this.validateUserStatus(user);
            await this.validateTokenVersion(payload);

            const foundDeviceToken = await this.getFoundDeviceToken(user.id, deviceToken);

            return this.buildAuthResponse(user, foundDeviceToken);
        } catch (error) {
            this.handleTokenErrors(error);
        }
    }

    async loginWithDeviceToken(deviceToken: string): Promise<AuthResponse> {
        try {
            const session = await this.findActiveSession(deviceToken);
            const user = session.user;

            this.validateUserStatus(user);

            const foundDeviceToken = await this.getFoundDeviceToken(user.id, deviceToken);

            return this.buildAuthResponse(user, foundDeviceToken);
        } catch (error) {
            if (error instanceof UnauthorizedException) {
                throw error;
            }
            this.handleDbExceptions(error);
        }
    }

    async generateDeviceToken(): Promise<DeviceTokenResponse> {
        try {
            const deviceToken = uuid();
            return {
                deviceToken,
                message: 'Device token generated successfully',
                note: 'This token must be saved using /save-device-token endpoint'
            };
        } catch (error) {
            this.handleDbExceptions(error);
        }
    }

    async saveDeviceToken(user: User, deviceToken: string): Promise<DeviceTokenResponse> {
        try {
            await this.validateDeviceTokenUniqueness(deviceToken, user.id);

            const session = await this.findOrCreateSession(user.id, deviceToken);
            session.isActive = true;
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
            this.handleDbExceptions(error);
        }
    }

    async updatePushToken(user: User, deviceToken: string, pushToken: string): Promise<DeviceTokenResponse> {
        try {
            const session = await this.sessionRepository.findOne({
                where: { userId: user.id, deviceToken }
            });

            if (!session) {
                throw new BadRequestException('Device token not found for this user. Make sure the device token is registered.');
            }

            session.pushToken = pushToken;
            await this.sessionRepository.save(session);

            return {
                deviceToken,
                message: 'Push token updated successfully',
                deviceStatus: 'registered'
            };
        } catch (error) {
            if (error instanceof BadRequestException) {
                throw error;
            }
            this.handleDbExceptions(error);
        }
    }

    async deactivatePushForSession(deviceToken: string) {
        try {
            const session = await this.sessionRepository.findOne({ where: { deviceToken } });

            if (!session) {
                throw new NotFoundException('Session not found');
            }

            session.pushActive = false;
            await this.sessionRepository.save(session);

            return {
                deviceToken: session.deviceToken || null,
                message: 'Push notifications deactivated for this session',
                deviceStatus: session.isActive ? 'registered' : 'inactive'
            };
        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            this.handleDbExceptions(error);
        }
    }

    async checkMainDevice(user: User, deviceToken: string): Promise<MainDeviceResponse> {
        try {
            const session = await this.sessionRepository.findOne({
                where: { userId: user.id, deviceToken }
            });

            if (!session) {
                return {
                    deviceToken,
                    isMainDevice: false,
                    message: 'Token de dispositivo no encontrado para este usuario',
                    requiresConfirmation: false,
                    confirmationMessage: undefined
                };
            }

            if (!session.isActive) {
                return {
                    deviceToken,
                    isMainDevice: false,
                    message: 'Este dispositivo pasará a ser el principal',
                    requiresConfirmation: true,
                    confirmationMessage: 'Este dispositivo está inactivo pero se convertirá en el dispositivo principal. ¿Desea continuar?'
                };
            }

            const activeSessions = await this.sessionRepository.find({
                where: { userId: user.id, isActive: true },
                order: { createdAt: 'ASC' }
            });

            if (activeSessions.length === 0) {
                return {
                    deviceToken,
                    isMainDevice: false,
                    message: 'No hay sesiones activas para este usuario',
                    requiresConfirmation: false,
                    confirmationMessage: undefined
                };
            }

            const mainDeviceSession = activeSessions[0];
            const isMainDevice = mainDeviceSession.deviceToken === deviceToken;

            if (isMainDevice) {
                return {
                    deviceToken,
                    isMainDevice: true,
                    message: 'Este dispositivo es el dispositivo principal',
                    requiresConfirmation: false,
                    confirmationMessage: undefined
                };
            } else {
                return {
                    deviceToken,
                    isMainDevice: false,
                    message: 'Este dispositivo no es el principal',
                    requiresConfirmation: true,
                    confirmationMessage: 'Este dispositivo pasará a ser el dispositivo principal. ¿Desea continuar?'
                };
            }
        } catch (error) {
            this.handleDbExceptions(error);
        }
    }

    async setMainDevice(user: User, deviceToken: string): Promise<MainDeviceResponse> {
        try {
            let wasActive = false;
            const session = await this.sessionRepository.findOne({
                where: { userId: user.id, deviceToken }
            });

            if (!session) {
                return {
                    deviceToken,
                    isMainDevice: false,
                    message: 'Token de dispositivo no encontrado para este usuario',
                    requiresConfirmation: false,
                    confirmationMessage: undefined
                };
            }

            wasActive = session.isActive;

            await this.sessionRepository.update(
                { userId: user.id, deviceToken: Not(deviceToken) },
                { isActive: false }
            );

            session.isActive = true;
            await this.sessionRepository.save(session);

            return {
                deviceToken,
                isMainDevice: true,
                message: 'Este dispositivo se ha convertido en el dispositivo principal',
                requiresConfirmation: wasActive ? false : true,
                confirmationMessage: undefined
            };
        } catch (error) {
            this.handleDbExceptions(error);
        }
    }

    async enableBiometrics(user: User, deviceToken: string): Promise<BiometricResponse> {
        try {
            const session = await this.findUserSession(user.id, deviceToken);
            this.validateSessionForBiometrics(session);

            if (session.biometricEnabled) {
                return {
                    message: 'Biometrics already enabled for this device',
                    deviceToken: session.deviceToken || undefined,
                    sessionId: session.id,
                    biometricEnabled: session.biometricEnabled
                };
            }

            session.biometricEnabled = true;
            await this.sessionRepository.save(session);

            return {
                deviceToken: session.deviceToken || undefined,
                sessionId: session.id,
                biometricEnabled: session.biometricEnabled,
                message: 'Biometrics enabled successfully for the specified device'
            };
        } catch (error) {
            if (error instanceof BadRequestException || error instanceof NotFoundException) {
                throw error;
            }
            this.handleDbExceptions(error);
        }
    }

    async disableBiometrics(userId: string, deviceToken?: string): Promise<BiometricResponse> {
        try {
            const user = await this.findUserById(userId);

            if (deviceToken) {
                return this.disableBiometricsForDevice(userId, deviceToken);
            } else {
                return this.disableBiometricsForAllDevices(userId);
            }
        } catch (error) {
            this.handleDbExceptions(error);
        }
    }

    async logoutAllDevices(): Promise<LogoutResponse> {
        try {
            await this.incrementGlobalSessionVersion();
            const result = await this.sessionRepository.update(
                { isActive: true },
                { isActive: false }
            );

            return {
                message: 'All devices have been logged out successfully',
                devicesLoggedOut: result.affected || 0
            };
        } catch (error) {
            this.handleDbExceptions(error);
        }
    }

    async logoutAllDevicesForUser(userId: string): Promise<LogoutResponse> {
        try {
            const user = await this.findUserById(userId);
            const result = await this.sessionRepository.update(
                { userId, isActive: true },
                { isActive: false }
            );

            return {
                message: `All devices for user ${user.email} have been logged out successfully`,
                devicesLoggedOut: result.affected || 0
            };
        } catch (error) {
            if (error instanceof NotFoundException) {
                throw error;
            }
            this.handleDbExceptions(error);
        }
    }

    private async findUserByEmail(email: string): Promise<User> {
        const user = await this.userRepository.findOne({
            where: { email },
            select: {
                id: true,
                email: true,
                password: true,
                fullName: true,
                isActive: true,
                roles: true,
                failedAttempts: true,
                blockedUntil: true,
                lastFailedAt: true
            }
        });

        if (!user) {
            throw new NotFoundException('Credentials are not valid (email)');
        }

        return user;
    }

    public async findUserById(userId: string): Promise<User> {
        const user = await this.userRepository.findOne({
            where: { id: userId },
            select: {
                id: true,
                email: true,
                fullName: true,
                isActive: true,
                roles: true,
            }
        });

        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        return user;
    }

    getTimeLeft(blockedUntil: Date): { minutes: number; seconds: number } {
        const now = new Date();
        const totalSeconds = Math.ceil((blockedUntil.getTime() - now.getTime()) / 1000);

        if (totalSeconds <= 0) {
            return { minutes: 0, seconds: 0 };
        }

        const minutes = Math.floor(totalSeconds / 60);
        const seconds = totalSeconds % 60;

        return { minutes, seconds };
    }

    private async validateUser(user: User, password: string): Promise<boolean> {
        const settings = await this.appSettingsRepository.findOne({ where: { id: this.DEFAULT_SETTINGS_ID } });
        const maxAttempts = settings?.maxLoginAttempts || 3;
        const blockDuration = settings?.loginBlockDurationMinutes || 90;

        if (user.blockedUntil && user.blockedUntil > new Date()) {
            const { minutes, seconds } = this.getTimeLeft(user.blockedUntil);
            throw new ForbiddenException({
                message: `Too many failed login attempts. Try again in ${minutes} minute(s) and ${seconds} second(s).`,
                error: 'TooManyAttempts',
                statusCode: 429,
                retryAfter: seconds * 1000,
            });
        }

        if (!bcrypt.compareSync(password, user.password)) {
            user.failedAttempts = (user.failedAttempts || 0) + 1;

            console.log("Failed attempts:", user.failedAttempts);
            if (user.failedAttempts >= maxAttempts) {
                user.blockedUntil = new Date(Date.now() + blockDuration * 60 * 1000);
                user.failedAttempts = 0;
                user.lastFailedAt = new Date();
            }

            await this.userRepository.save(user);

            return false;
        }

        user.failedAttempts = 0;
        user.blockedUntil = undefined;
        await this.userRepository.save(user);

        this.validateUserStatus(user);

        return true
    }

    private validateUserStatus(user: User): void {
        if (!user.isActive) {
            throw new UnauthorizedException('User is inactive, talk with an admin');
        }
    }

    private validateTokenFormat(token: string): void {
        if (!token || typeof token !== 'string' || token.trim().length === 0) {
            throw new UnauthorizedException('Invalid token format');
        }
    }

    private decodeAndValidateToken(token: string): JwtPayload {
        const payload = this.jwtService.verify(token) as JwtPayload;

        if (!payload || !payload.id || typeof payload.id !== 'string') {
            throw new UnauthorizedException('Invalid token payload');
        }

        return payload;
    }

    private async validateTokenVersion(payload: JwtPayload): Promise<void> {
        const appSettings = await this.getAppSettings();
        if (payload.sessionVersion !== undefined &&
            payload.sessionVersion < appSettings.globalSessionVersion) {
            throw new UnauthorizedException('Token has been invalidated by system administrator');
        }
    }

    private async getJwtToken(payload: JwtPayload): Promise<string> {
        const appSettings = await this.getAppSettings();
        const tokenPayload: JwtPayload = {
            ...payload,
            sessionVersion: appSettings.globalSessionVersion
        };

        const expiresIn = `${appSettings.defaultMaxSessionMinutes}m`;

        return this.jwtService.sign(tokenPayload, {
            expiresIn
        });
    }

    private async findActiveSession(deviceToken: string): Promise<Session> {
        const session = await this.sessionRepository.findOne({
            where: { deviceToken },
            relations: ['user']
        });

        if (!session || !session.user) {
            throw new UnauthorizedException('Invalid device token');
        }

        return session;
    }

    private async findUserSession(userId: string, deviceToken: string): Promise<Session> {
        const session = await this.sessionRepository.findOne({
            where: { userId, deviceToken }
        });

        if (!session) {
            throw new NotFoundException('Device token not found for this user. Make sure the device token is registered.');
        }

        return session;
    }

    private async findOrCreateSession(userId: string, deviceToken: string): Promise<Session> {
        let session = await this.sessionRepository.findOne({
            where: { userId, deviceToken }
        });

        if (!session) {
            session = this.sessionRepository.create({
                userId,
                deviceToken,
                isActive: true
            });
        }

        return session;
    }

    private validateSessionForBiometrics(session: Session): void {
        if (!session.isActive) {
            throw new BadRequestException('The specified device session is inactive. Please activate the session first.');
        }
    }

    private validateBiometricEnabled(session: Session): void {
        if (!session.biometricEnabled) {
            throw new UnauthorizedException('Biometrics not enabled for this device');
        }
    }

    private async getAllDeviceTokens(userId: string): Promise<DeviceTokenInfo[]> {
        const sessions = await this.sessionRepository.find({
            where: { userId },
            select: ['id', 'deviceToken', 'isActive', 'biometricEnabled', 'pushToken', 'pushActive']
        });

        return sessions
            .filter(session => session.deviceToken)
            .map(session => ({
                deviceToken: session.deviceToken!,
                isActive: session.isActive,
                sessionId: session.id,
                biometricEnabled: session.biometricEnabled,
                pushToken: session.pushToken || null,
                pushActive: session.pushActive || undefined
            }));
    }

    private async getFoundDeviceToken(userId: string, deviceToken?: string): Promise<FoundDeviceTokenInfo | null> {
        if (!deviceToken) {
            return null;
        }

        const deviceTokens = await this.getAllDeviceTokens(userId);
        const deviceTokenInfo = deviceTokens.find(token => token.deviceToken === deviceToken);

        if (!deviceTokenInfo) {
            return null;
        }

        return {
            deviceToken: deviceTokenInfo.deviceToken,
            isActive: deviceTokenInfo.isActive,
            sessionId: deviceTokenInfo.sessionId,
            biometricEnabled: deviceTokenInfo.biometricEnabled,
            pushToken: deviceTokenInfo.pushToken || null,
            pushActive: deviceTokenInfo.pushActive,
            message: 'Device token found successfully'
        };
    }

    private async validateDeviceTokenUniqueness(deviceToken: string, userId: string): Promise<void> {
        const existingSession = await this.sessionRepository.findOne({
            where: { deviceToken, isActive: true }
        });

        if (existingSession && existingSession.userId !== userId) {
            throw new BadRequestException('This device token is already in use by another account');
        }
    }

    private async disableBiometricsForDevice(userId: string, deviceToken: string): Promise<BiometricResponse> {
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
            deviceToken: session.deviceToken || undefined,
            sessionId: session.id
        };
    }

    private async disableBiometricsForAllDevices(userId: string): Promise<BiometricResponse> {
        await this.sessionRepository.update(
            { userId },
            { biometricEnabled: false }
        );

        await this.sessionRepository.update(
            { userId, isActive: true },
            { isActive: false }
        );

        return {
            message: 'Biometrics disabled successfully for all devices'
        };
    }

    private async getAppSettings(): Promise<AppSettings> {
        let settings = await this.appSettingsRepository.findOne({
            where: { id: this.DEFAULT_SETTINGS_ID }
        });

        if (!settings) {
            settings = this.appSettingsRepository.create({
                id: this.DEFAULT_SETTINGS_ID,
                allowMultipleSessions: true,
                globalSessionVersion: 0,
                defaultMaxSessionMinutes: 2,
            });
            settings = await this.appSettingsRepository.save(settings);
        }

        return settings;
    }

    private async buildAuthResponse(user: User, foundDeviceToken: FoundDeviceTokenInfo | null): Promise<AuthResponse> {
        const appSettings = await this.getAppSettings();
        const token = await this.getJwtToken({ id: user.id });
        const refreshToken = await this.generateRefreshToken({ id: user.id });

        return {
            id: user.id,
            email: user.email,
            fullName: user.fullName,
            isActive: user.isActive,
            roles: user.roles,
            foundDeviceToken,
            allowMultipleSessions: appSettings.allowMultipleSessions,
            token,
            refreshToken
        };
    }

    private async generateRefreshToken(payload: { id: string }): Promise<string> {
        const expiresIn = '2m';
        const { envs } = await import('../config');
        return this.jwtService.sign(
            { ...payload, type: 'refresh' },
            {
                secret: envs.JWT_PRIVATE_SECRET,
                expiresIn
            }
        );
    }

    private async incrementGlobalSessionVersion(): Promise<void> {
        const settings = await this.getAppSettings();
        settings.globalSessionVersion += 1;
        await this.appSettingsRepository.save(settings);
    }

    private handleTokenErrors(error: any): never {
        if (error.name === 'JsonWebTokenError') {
            throw new UnauthorizedException('Invalid token signature');
        }
        if (error.name === 'TokenExpiredError') {
            throw new UnauthorizedException('Token has expired');
        }
        if (error.name === 'NotBeforeError') {
            throw new UnauthorizedException('Token not active yet');
        }
        if (error instanceof UnauthorizedException) {
            throw error;
        }

        this.logger.error('Error verifying JWT token:', error);
        throw new UnauthorizedException('Token validation failed');
    }

    private handleDbExceptions(error: any): never {
        if (error.code === '23505') {
            throw new BadRequestException(error.detail);
        }

        this.logger.error('Database error:', error);
        throw new InternalServerErrorException('Unexpected server error');
    }
}