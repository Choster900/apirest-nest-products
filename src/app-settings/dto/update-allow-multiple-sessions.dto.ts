import { IsBoolean, IsOptional } from 'class-validator';

export class UpdateAllowMultipleSessionsDto {
  @IsBoolean({ message: 'allowMultipleSessions must be a boolean value' })
  allowMultipleSessions: boolean;

  @IsBoolean({ message: 'forceLogoutAll must be a boolean value' })
  @IsOptional()
  forceLogoutAll?: boolean = true;
}
