import { IsBoolean, IsOptional } from 'class-validator';

export class UpdateAllowMultipleSessionsDto {
  @IsBoolean()
  allowMultipleSessions: boolean;

  @IsBoolean()
  @IsOptional()
  forceLogoutAll?: boolean = true;
}
