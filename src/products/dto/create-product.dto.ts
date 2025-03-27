import { IsString, IsOptional, IsNumber, IsArray, IsIn, Min, IsPositive, MinLength, IsInt } from 'class-validator';

export class CreateProductDto {
    @IsString()
    @MinLength(1)
    title: string;

    @IsOptional()
    @IsNumber()
    @IsPositive()
    price?: number;

    @IsOptional()
    @IsString()
    description?: string;

    @IsOptional()
    @IsString()
    slug?: string;

    @IsOptional()
    @IsInt()
    @Min(0)
    @IsPositive()
    stock?: number;

    @IsArray()
    @IsString({ each: true })
    sizes: string[];

    @IsString()
    @IsIn(['male', 'female', 'unisex', 'men'])
    gender: string;

    @IsArray()
    @IsString({ each: true })
    tags: string[]
}
