import { IsNumber, IsOptional, Min, Max } from 'class-validator';

export class UpdateDefaultsDto {
  @IsNumber({}, { message: 'defaultMaxSessionMinutes must be a number' })
  @Min(1, { message: 'Session duration must be at least 1 minute' })
  @Max(43200, { message: 'Session duration cannot exceed 30 days (43200 minutes)' })
  @IsOptional()
  defaultMaxSessionMinutes?: number;
}
