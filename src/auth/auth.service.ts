import {
    BadRequestException,
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

/**
 * Authentication service handling user registration, login, token management, and device sessions
 */
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

    // ==============================
    // PUBLIC AUTH METHODS
    // ==============================

    /**
     * Finds user by email for validation purposes (doesn't throw if not found)
     */
    async findUserByEmailForValidation(email: string): Promise<User | null> {
        return await this.userRepository.findOne({
            where: { email },
            select: ['id', 'email']
        });
    }

    /**
     * Generates a public token for authentication access
     */
    async generatePublicToken(): Promise<{ token: string; expiresIn: string }> {
        const payload = {
            isPublicKey: true,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60) // 1 año
        };

        const token = this.jwtService.sign(payload, {
            secret: envs.JWT_PUBLIC_SECRET
        });

        return {
            token,
            expiresIn: '365d'
        };
    }

    /**
     * Refreshes access token using a valid refresh token
     */
    async refreshTokens(userId: string, deviceToken?: string): Promise<AuthResponse> {
        const user = await this.findUserById(userId);
        this.validateUserStatus(user);

        // Validar versión de sesión actual
        const appSettings = await this.getAppSettings();
        // No necesitamos validar sessionVersion aquí porque el refresh token ya fue validado por el guard

        // Get device token information if provided
        const foundDeviceToken = await this.getFoundDeviceToken(user.id, deviceToken);

        // Generar nuevos tokens
        return this.buildAuthResponse(user, foundDeviceToken);
    }

    /**
     * Creates a new user account
     */
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

    /**
     * Authenticates user with email/password and optional device token
     */
    async login(loginUserDto: LoginUserDto): Promise<AuthResponse> {
        const { password, email, deviceToken } = loginUserDto;

        // Find and validate user
        const user = await this.findUserByEmail(email);
        console.log("user found:", user);
        const isValid = await this.validateUser(user, password);
        if (!isValid) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // Get device token information if provided
        const foundDeviceToken = await this.getFoundDeviceToken(user.id, deviceToken);

        return this.buildAuthResponse(user, foundDeviceToken);
    }

    /**
     * Verifies JWT token and optionally returns device token info
     */
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

    /**
     * Authenticates user using device token (biometric login)
     */
    async loginWithDeviceToken(deviceToken: string): Promise<AuthResponse> {
        try {
            const session = await this.findActiveSession(deviceToken);
            const user = session.user;

            this.validateUserStatus(user);
            //this.validateBiometricEnabled(session);

            const foundDeviceToken = await this.getFoundDeviceToken(user.id, deviceToken);

            return this.buildAuthResponse(user, foundDeviceToken);
        } catch (error) {
            if (error instanceof UnauthorizedException) {
                throw error;
            }
            this.handleDbExceptions(error);
        }
    }

    // ==============================
    // DEVICE TOKEN MANAGEMENT
    // ==============================

    /**
     * Generates a new device token
     */
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

    /**
     * Saves a device token for a user
     */
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

    /**
     * Checks if a device token is the main device for the user
     */
    async checkMainDevice(user: User, deviceToken: string): Promise<MainDeviceResponse> {
        try {
            // Find the session for this device token
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

            // Check if the device token session is inactive
            if (!session.isActive) {
                return {
                    deviceToken,
                    isMainDevice: false,
                    message: 'Este dispositivo pasará a ser el principal',
                    requiresConfirmation: true,
                    confirmationMessage: 'Este dispositivo está inactivo pero se convertirá en el dispositivo principal. ¿Desea continuar?'
                };
            }

            // Get all active sessions for the user
            const activeSessions = await this.sessionRepository.find({
                where: { userId: user.id, isActive: true },
                order: { createdAt: 'ASC' } // Order by creation date to find the first (main) device
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

            // The main device is the first active session created
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
            // Solo lanzar errores de base de datos, no errores de lógica de negocio
            this.handleDbExceptions(error);
        }
    }

    /**
     * Sets a device as the main device, deactivating all others
     */
    async setMainDevice(user: User, deviceToken: string): Promise<MainDeviceResponse> {
        try {

            let wasActive = false;
            // Find the session for this device token
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

            // Check if the device token session is inactive
            wasActive = session.isActive;

            // Deactivate all other devices for this user
            await this.sessionRepository.update(
                { userId: user.id, deviceToken: Not(deviceToken) },
                { isActive: false }
            );

            // Activate this device as main device
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

    // ==============================
    // BIOMETRIC MANAGEMENT
    // ==============================

    /**
     * Enables biometrics for a specific device
     */
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

    /**
     * Disables biometrics for specific device or all devices
     */
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

    // ==============================
    // LOGOUT OPERATIONS
    // ==============================

    /**
     * Logs out all devices globally
     */
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

    /**
     * Logs out all devices for a specific user
     */
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

    // ==============================
    // PRIVATE HELPER METHODS - USER OPERATIONS
    // ==============================

    /**
     * Finds user by email with password for authentication
     */
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

    /**
     * Finds user by ID
     */
    private async findUserById(userId: string): Promise<User> {
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
    /**
     * Validates user credentials
     */
    private async validateUser(user: User, password: string): Promise<boolean> {

        // Check if user is blocked due to too many failed attempts
        if (user.blockedUntil && user.blockedUntil > new Date()) {
            const { minutes, seconds } = this.getTimeLeft(user.blockedUntil);
            throw new UnauthorizedException(`Too many failed login attempts. Try again in ${minutes} minute(s) and ${seconds} second(s).`);
        }

        if (!bcrypt.compareSync(password, user.password)) {

            user.failedAttempts = (user.failedAttempts || 0) + 1;

            console.log("Failed attempts:", user.failedAttempts);
            if (user.failedAttempts >= 3) {
                user.blockedUntil = new Date(Date.now() + 1.5 * 60 * 1000); // 1.5 minutos
                user.failedAttempts = 0; // resetear para próximo intento
                user.lastFailedAt = new Date();
            }

            await this.userRepository.save(user);

            //throw new UnauthorizedException('Credentials are not valid (password)');

            return false;
        }

        // Reset failed attempts on successful login
        user.failedAttempts = 0;
        user.blockedUntil = undefined;
        await this.userRepository.save(user);

        this.validateUserStatus(user);

        return true
    }

    /**
     * Validates user status
     */
    private validateUserStatus(user: User): void {
        if (!user.isActive) {
            throw new UnauthorizedException('User is inactive, talk with an admin');
        }
    }

    // ==============================
    // PRIVATE HELPER METHODS - TOKEN OPERATIONS
    // ==============================

    /**
     * Validates token format
     */
    private validateTokenFormat(token: string): void {
        if (!token || typeof token !== 'string' || token.trim().length === 0) {
            throw new UnauthorizedException('Invalid token format');
        }
    }

    /**
     * Decodes and validates JWT token
     */
    private decodeAndValidateToken(token: string): JwtPayload {
        const payload = this.jwtService.verify(token) as JwtPayload;

        if (!payload || !payload.id || typeof payload.id !== 'string') {
            throw new UnauthorizedException('Invalid token payload');
        }

        return payload;
    }

    /**
     * Validates token version against global session version
     */
    private async validateTokenVersion(payload: JwtPayload): Promise<void> {
        const appSettings = await this.getAppSettings();
        if (payload.sessionVersion !== undefined &&
            payload.sessionVersion < appSettings.globalSessionVersion) {
            throw new UnauthorizedException('Token has been invalidated by system administrator');
        }
    }

    /**
     * Generates JWT token with current session version
     */
    private async getJwtToken(payload: JwtPayload): Promise<string> {
        const appSettings = await this.getAppSettings();
        const tokenPayload: JwtPayload = {
            ...payload,
            sessionVersion: appSettings.globalSessionVersion
        };

        // Use the configured session duration from app settings
        const expiresIn = `${appSettings.defaultMaxSessionMinutes}m`;

        return this.jwtService.sign(tokenPayload, {
            expiresIn
        });
    }

    // ==============================
    // PRIVATE HELPER METHODS - SESSION OPERATIONS
    // ==============================

    /**
     * Finds active session by device token
     */
    private async findActiveSession(deviceToken: string): Promise<Session> {
        const session = await this.sessionRepository.findOne({
            where: { deviceToken/* , isActive: true  */ },
            relations: ['user']
        });

        if (!session || !session.user) {
            throw new UnauthorizedException('Invalid device token');
        }

        return session;
    }

    /**
     * Finds user session by user ID and device token
     */
    private async findUserSession(userId: string, deviceToken: string): Promise<Session> {
        const session = await this.sessionRepository.findOne({
            where: { userId, deviceToken }
        });

        if (!session) {
            throw new NotFoundException('Device token not found for this user. Make sure the device token is registered.');
        }

        return session;
    }

    /**
     * Finds or creates a session for user and device token
     */
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

    /**
     * Validates session for biometric operations
     */
    private validateSessionForBiometrics(session: Session): void {
        if (!session.isActive) {
            throw new BadRequestException('The specified device session is inactive. Please activate the session first.');
        }
    }

    /**
     * Validates biometric is enabled for session
     */
    private validateBiometricEnabled(session: Session): void {
        if (!session.biometricEnabled) {
            throw new UnauthorizedException('Biometrics not enabled for this device');
        }
    }

    // ==============================
    // PRIVATE HELPER METHODS - DEVICE TOKEN OPERATIONS
    // ==============================

    /**
     * Gets all device tokens for a user
     */
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

    /**
     * Gets found device token information if deviceToken is provided
     */
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
            message: 'Device token found successfully'
        };
    }

    /**
     * Validates device token uniqueness across users
     */
    private async validateDeviceTokenUniqueness(deviceToken: string, userId: string): Promise<void> {
        const existingSession = await this.sessionRepository.findOne({
            where: { deviceToken, isActive: true }
        });

        if (existingSession && existingSession.userId !== userId) {
            throw new BadRequestException('This device token is already in use by another account');
        }
    }

    // ==============================
    // PRIVATE HELPER METHODS - BIOMETRIC OPERATIONS
    // ==============================

    /**
     * Disables biometrics for specific device
     */
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

    /**
     * Disables biometrics for all user devices
     */
    private async disableBiometricsForAllDevices(userId: string): Promise<BiometricResponse> {
        // Disable biometrics for all sessions
        await this.sessionRepository.update(
            { userId },
            { biometricEnabled: false }
        );

        // Deactivate all user sessions
        await this.sessionRepository.update(
            { userId, isActive: true },
            { isActive: false }
        );

        return {
            message: 'Biometrics disabled successfully for all devices'
        };
    }

    // ==============================
    // PRIVATE HELPER METHODS - SETTINGS & RESPONSE
    // ==============================

    /**
     * Gets or creates app settings
     */
    private async getAppSettings(): Promise<AppSettings> {
        let settings = await this.appSettingsRepository.findOne({
            where: { id: this.DEFAULT_SETTINGS_ID }
        });

        if (!settings) {
            settings = this.appSettingsRepository.create({
                id: this.DEFAULT_SETTINGS_ID,
                allowMultipleSessions: true,
                globalSessionVersion: 0,
                defaultMaxSessionMinutes: 2, // 2 minutes expiration
            });
            settings = await this.appSettingsRepository.save(settings);
        }

        return settings;
    }

    /**
     * Builds standardized auth response
     */
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

    /**
     * Generates a refresh token with longer expiration
     */
    private async generateRefreshToken(payload: { id: string }): Promise<string> {
        // 30 días por defecto
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

    /**
     * Increments global session version to invalidate all tokens
     */
    private async incrementGlobalSessionVersion(): Promise<void> {
        const settings = await this.getAppSettings();
        settings.globalSessionVersion += 1;
        await this.appSettingsRepository.save(settings);
    }

    // ==============================
    // ERROR HANDLING
    // ==============================

    /**
     * Handles token-specific errors
     */
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

    /**
     * Handles database exceptions
     */
    private handleDbExceptions(error: any): never {
        if (error.code === '23505') {
            throw new BadRequestException(error.detail);
        }

        this.logger.error('Database error:', error);
        throw new InternalServerErrorException('Unexpected server error');
    }
}