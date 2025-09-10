import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { FilesService } from './files.service';
import { FilesController } from './files.controller';

@Module({
  imports: [ConfigModule],
  controllers: [FilesController],
  providers: [FilesService],
})
export class FilesModule {}
