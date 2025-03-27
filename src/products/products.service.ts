import { BadRequestException, HttpCode, HttpStatus, Injectable, InternalServerErrorException, Logger, NotFoundException } from '@nestjs/common';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';
import { Product } from './entities/product.entity';
import { PaginationDto } from 'src/common/dtos/pagination.dto';
import { validate as isUUID } from 'uuid'
import { ProductImage } from './entities';
@Injectable()
export class ProductsService {

    private readonly logger = new Logger('ProducsServices')

    constructor(
        @InjectRepository(Product) private readonly productRepository: Repository<Product>,

        @InjectRepository(ProductImage) private readonly productImageRepository: Repository<ProductImage>,

        private readonly dataSource: DataSource
    ) { }

    async create(createProductDto: CreateProductDto) {
        try {
            //! En el DTO hay un metodo llamado beforeInsert que modifica la data

            const { images = [], ...productDetails } = createProductDto

            const product = this.productRepository.create({
                ...productDetails,
                images: images.map(image => this.productImageRepository.create({ url: image }))
            })
            await this.productRepository.save(product)

            return { ...product, images }

        } catch (error) {
            this.handleDbExecptions(error)
        }
    }

    async findAll(paginationDto: PaginationDto) {

        const { limit, offset } = paginationDto;

        try {
            const products = await this.productRepository.find({
                take: limit,
                skip: offset,
                relations: {
                    images: true,
                }
            });

            return products.map(product => ({
                ...product,
                images: (product.images ?? []).map(image => ({ url: image.url }))
            }));

        } catch (error) {
            this.handleDbExecptions(error);
        }

    }

    async findOne(term: string) {

        let product: Product | null = null;

        if (isUUID(term)) {
            product = await this.productRepository.findOneBy({ id: term });
        } else {
            // product = await this.productRepository.findOneBy({ slug : term });
            const queryBuilder = this.productRepository.createQueryBuilder('prod')

            product = await queryBuilder
                .where('UPPER(title) = :title or slug = :slug', {
                    title: term.toUpperCase(),
                    slug: term
                })
                .leftJoinAndSelect('prod.images', 'ProdImages')
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


    async finOnePlain(term: string) {
        const { images = [], ...rest } = await this.findOne(term)

        return {
            ...rest,
            images: images.map(img => img.url)
        }
    }

    async update(id: string, updateProductDto: UpdateProductDto) {


        const queryRunner = this.dataSource.createQueryRunner()

        await queryRunner.connect()

        await queryRunner.startTransaction()

        try {

            const { images, ...toUpdate } = updateProductDto

            const producto = await this.productRepository.preload({
                id: id,
                ...toUpdate,
                //images: []
            })

            if (images) {
                await queryRunner.manager.delete(ProductImage, {
                    product: { id }
                })


                if (producto) {
                    producto.images = images
                        .map(image => this.productImageRepository
                            .create({ url: image }));
                }

            }

            if (!producto) throw new NotFoundException({
                message: `Product with id ${id} not found`,
                status: HttpStatus.NOT_FOUND
            })

            await queryRunner.manager.save(producto)

            await queryRunner.commitTransaction();

            await queryRunner.release()
            //await this.productRepository.save(producto)
            return this.finOnePlain(id)


        } catch (error) {

            await queryRunner.rollbackTransaction()

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

    async deleteAllProducts() {
        const query = this.productRepository.createQueryBuilder('product')

        try {
            return await query
                .delete()
                .where({})
                .execute()

        } catch (error) {
            this.handleDbExecptions(error)
        }
    }
}
