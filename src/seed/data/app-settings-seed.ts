interface SeedAppSettings {
  id: number;
  allowMultipleSessions: boolean;
  globalSessionVersion: number;
  defaultMaxSessionMinutes: number;
  isActive: boolean;
}

interface SeedData {
  appSettings: SeedAppSettings;
}

export const initialAppSettingsData: SeedData = {
  appSettings: {
    id: 1,
    allowMultipleSessions: true,
    globalSessionVersion: 0,
    defaultMaxSessionMinutes: 60,
    isActive: true,
  },
};
