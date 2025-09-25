export interface DeviceTokenInfo {
    deviceToken: string;
    isActive: boolean;
    sessionId: string;
    biometricEnabled: boolean;
    pushToken?: string;
    pushActive?: boolean;
}
