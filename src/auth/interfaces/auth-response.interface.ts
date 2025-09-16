/**
 * Common auth response interface that standardizes all authentication endpoint responses
 */
export interface AuthResponse {
  id: string;
  email: string;
  fullName: string;
  isActive: boolean;
  roles: string[];
  foundDeviceToken: FoundDeviceTokenInfo | null;
  allowMultipleSessions: boolean;
  token: string;
}

/**
 * Extended device token information returned in auth responses
 */
export interface FoundDeviceTokenInfo {
  deviceToken: string;
  isActive: boolean;
  sessionId: string;
  biometricEnabled: boolean;
  message: string;
}

/**
 * Response for device token operations
 */
export interface DeviceTokenResponse {
  deviceToken: string;
  message: string;
  sessionId?: string;
  biometricEnabled?: boolean;
  deviceStatus?: string;
  note?: string;
}

/**
 * Response for logout operations
 */
export interface LogoutResponse {
  message: string;
  devicesLoggedOut: number;
}

/**
 * Response for biometric operations
 */
export interface BiometricResponse {
  deviceToken?: string;
  sessionId?: string;
  biometricEnabled?: boolean;
  message: string;
}

/**
 * Response for main device verification
 */
export interface MainDeviceResponse {
  deviceToken: string;
  isMainDevice: boolean;
  message: string;
  requiresConfirmation?: boolean;
  confirmationMessage?: string;
}