import { Controller, Get, Post, Param, UploadedFile, UseInterceptors, BadRequestException, Res, Headers } from '@nestjs/common';
import { Response } from 'express';
import { FilesService } from './files.service';
import { FileInterceptor } from '@nestjs/platform-express';
import { fileFilter, fileNamer } from './helpers';
import { diskStorage } from 'multer';
import { ConfigModule } from '@nestjs/config';


@Controller('files')
export class FilesController {
    constructor(
        private readonly filesService: FilesService,
        private readonly ConfigModule
    ) { }


    @Get('product/:imageName')
    findProductImage(
        @Res() res: Response,
        @Param('imageName') imageName: string
    ) {

        const path = this.filesService.getStaticProductImage(imageName)

        res.sendFile(path)
    }


    @Post("product")
    @UseInterceptors(FileInterceptor('file', {
        fileFilter: fileFilter,
        //limits: { fileSize: 1000}
        storage: diskStorage({
            destination: './static/products',
            filename: fileNamer
        })
    }))
    uploadProductImage(
        @UploadedFile() file: Express.Multer.File,
        @Headers() headers
    ) {
        if (!file) {
            throw new BadRequestException('Asegúrate de que haya un archivo en el body');
        }

        const protocol = headers['x-forwarded-proto'] || 'http'; // Detecta si es http o https
        const host = headers.host;

        const secureUrl = `${protocol}://${host}/api/files/product/${file.filename}`;

        return {
            secureUrl
        };
    }



    /*

async login (@Headers() headers) {
  console.log('AUTHH LOGG', headers.host)
}
  */
}
