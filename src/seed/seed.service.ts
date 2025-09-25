import { Injectable } from '@nestjs/common';
import { ProductsService } from './../products/products.service';
import { AppSettingsService } from '../app-settings/app-settings.service';
import { initialData } from './data/seed-data';
import { initialAppSettingsData } from './data/app-settings-seed';

@Injectable()
export class SeedService {

    constructor(
        private readonly productService: ProductsService,
        private readonly appSettingsService: AppSettingsService
    ) { }

    async runSeed() {

        // Seed App Settings first
        await this.seedAppSettings();

        await this.insertNewProducts()

        const seedProducts = initialData.products

        const insertsPromises: Promise<any>[] = []

        seedProducts.forEach(product => {

            insertsPromises.push(this.productService.create(product))
        })

        await Promise.all(insertsPromises)

        return 'SEED EXECUTED'
    }

    async runAppSettingsSeed() {
        await this.seedAppSettings();
        return 'APP SETTINGS SEED EXECUTED';
    }

    private async insertNewProducts() {
        await this.productService.deleteAllProducts()

        return true
    }

    private async seedAppSettings() {
        try {
            // Check if settings already exist
            const existingSettings = await this.appSettingsService.get();

            if (existingSettings) {
                console.log('App Settings already exist, skipping seed...');
                return existingSettings;
            }
        } catch (error) {
            // Settings don't exist, proceed with seeding
            console.log('Creating initial app settings...');
        }

        // Create initial settings using the seed data
        const settingsData = initialAppSettingsData.appSettings;

        // Since the service's get() method creates settings with defaults from env,
        // we'll let it handle the creation and then update if needed
        const settings = await this.appSettingsService.get();

        console.log('App Settings seeded successfully');
        return settings;
    }
}
