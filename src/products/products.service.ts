import { BadRequestException, HttpCode, HttpStatus, Injectable, InternalServerErrorException, Logger, NotFoundException } from '@nestjs/common';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Product } from './entities/product.entity';
import { PaginationDto } from 'src/common/dtos/pagination.dto';
import { validate as isUUID } from 'uuid'
@Injectable()
export class ProductsService {

    private readonly logger = new Logger('ProducsServices')

    constructor(
        @InjectRepository(Product) private readonly productRepository: Repository<Product>
    ) { }

    async create(createProductDto: CreateProductDto) {
        try {

            //! En el DTO hay un metodo llamado beforeInsert que modifica la data
            const product = this.productRepository.create(createProductDto)
            await this.productRepository.save(product)

            return product

        } catch (error) {
            this.handleDbExecptions(error)
        }
    }

    async findAll(paginationDto: PaginationDto) {

        const { limit, offset } = paginationDto

        try {
            const products = await this.productRepository.find({
                take: limit,
                skip: offset
            });

            return products

        } catch (error) {
            this.handleDbExecptions(error)
        }

    }

    async findOne(term: string) {

        let product: Product | null = null;

        if (isUUID(term)) {
            product = await this.productRepository.findOneBy({ id: term });
        } else {
            // product = await this.productRepository.findOneBy({ slug : term });
            const queryBuilder = this.productRepository.createQueryBuilder()

            product = await queryBuilder
                .where('UPPER(title) = :title or slug = :slug', {
                    title: term.toUpperCase(),
                    slug: term
                })
                .getOne();

        }

        if (!product) {
            throw new NotFoundException({
                message: `Product with id ${term} not found`,
                status: HttpStatus.NOT_FOUND
            })
        }

        return product


    }

    async update(id: string, updateProductDto: UpdateProductDto) {

        try {
            const producto = await this.productRepository.preload({
                id: id,
                ...updateProductDto
            })

            if (!producto) throw new NotFoundException({
                message: `Product with id ${id} not found`,
                status: HttpStatus.NOT_FOUND
            })

            await this.productRepository.save(producto)

            return producto
        } catch (error) {
            this.handleDbExecptions(error)

        }



    }

    async remove(id: string) {

        const product = await this.findOne(id);


        await this.productRepository.remove(product);

        return { message: `Product with id ${id} has been removed` };

    }

    private handleDbExecptions(error: any) {
        if (error.code === '23505')
            throw new BadRequestException(error.detail)

        this.logger.error(error)

        throw new InternalServerErrorException('Error inesperado en el servidor')
    }
}
