import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { envs } from './config';
import { ProductsModule } from './products/products.module';
import { CommonModule } from './common/common.module';
import { SeedModule } from './seed/seed.module';
import { FilesModule } from './files/files.module';

@Module({
    imports: [
        ConfigModule.forRoot(),
        TypeOrmModule.forRoot({
            type: 'postgres',
            host: envs.POSTGRES_HOST,
            port: envs.POSTGRES_PORT,
            database: envs.POSTGRES_DB,
            username: envs.POSTGRES_USER,
            password: envs.POSTGRES_PASSWORD,
            autoLoadEntities: true,
            synchronize: true
        }),
        ProductsModule,
        CommonModule,
        SeedModule,
        FilesModule


    ],
    controllers: [],
    providers: [],
})
export class AppModule { }
