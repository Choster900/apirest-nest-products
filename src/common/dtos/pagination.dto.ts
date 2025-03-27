import { Type } from "class-transformer";
import { IsOptional, IsPositive, Min } from "class-validator";

export class PaginationDto {

    @IsPositive()
    @IsOptional()
    @Type( () => Number)
    limit?: number;


    @IsOptional()
    @Type( () => Number)
    @Min(0)
    offset?: number;
}
