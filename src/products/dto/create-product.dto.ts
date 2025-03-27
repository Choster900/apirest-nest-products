import { IsString, IsOptional, IsNumber, IsArray, IsIn, Min, IsPositive, MinLength, IsInt } from 'class-validator';
import { ProductImage } from '../entities';

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
    @IsIn(['men', 'women', 'kid', 'unisex'])
    gender: string;

    @IsArray()
    @IsString({ each: true })
    tags: string[]

    @IsArray()
    @IsString({ each: true })
    images?: string[]
}
