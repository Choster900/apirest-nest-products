import { Controller, Get, Post, Body, Patch, Param, Delete, UploadedFile, UseInterceptors, BadRequestException } from '@nestjs/common';
import { FilesService } from './files.service';
import { FileInterceptor } from '@nestjs/platform-express';
import { fileFilter, fileNamer } from './helpers';
import { diskStorage } from 'multer';


@Controller('files')
export class FilesController {
    constructor(private readonly filesService: FilesService) { }


    


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
        @UploadedFile() file: Express.Multer.File
    ) {

        if (!file) {
            throw new BadRequestException('Asegurate de que haya un archivo en el body')
        }

        console.log(file);

        const secureUrl = `${ file.filename }`

        return {
            fileName: secureUrl
        }
    }
}
