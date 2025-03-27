import { Injectable } from '@nestjs/common';
import { ProductsService } from './../products/products.service';
import { initialData } from './data/seed-data';

@Injectable()
export class SeedService {

    constructor(
        private readonly productService: ProductsService
    ) { }

    async runSeed() {

        await this.insertNewProducts()

        const seedProducts = initialData.products

        const insertsPromises: Promise<any>[] = []

        seedProducts.forEach(product => {

            insertsPromises.push(this.productService.create(product))
        })

        await Promise.all(insertsPromises)

        return 'SEED EXECUTED'
    }

    private async insertNewProducts() {
        await this.productService.deleteAllProducts()

        return true
    }
}
