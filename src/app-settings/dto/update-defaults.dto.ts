import { IsNumber, IsOptional, Min } from 'class-validator';

export class UpdateDefaultsDto {
  @IsNumber()
  @Min(1)
  @IsOptional()
  defaultMaxSessionMinutes?: number;
}
