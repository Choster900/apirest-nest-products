import { IsBoolean, IsNumber, IsOptional, Min, Max, isNumber } from 'class-validator';

export class UpdateAllSettingsDto {


  @IsBoolean({ message: 'allowMultipleSessions must be a boolean value' })
  allowMultipleSessions?: boolean;


  @IsNumber({}, { message: 'defaultMaxSessionMinutes must be a number' })
  @Min(1, { message: 'Default max session minutes must be at least 1 minute' })
  @Max(43200, { message: 'Default max session minutes cannot exceed 30 days (43200 minutes)' })
  defaultMaxSessionMinutes?: number;


  @IsBoolean({ message: 'forceLogoutAll must be a boolean value' })
  forceLogoutAll?: boolean;

  @IsNumber()
  loginBlockDurationMinutes? : number

  @IsNumber()
  maxLoginAttempts?: number


  
}
