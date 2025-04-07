import { Controller, Post, UploadedFile, UseInterceptors} from '@nestjs/common';
import { FilesService } from './files.service';
import { FilesInterceptor } from '@nestjs/platform-express';

@Controller('files')
export class FilesController {
  constructor(private readonly filesService: FilesService) {}

  @Post('image-profile')
  @UseInterceptors(FilesInterceptor('file'))
  async uploadImageProfile( @UploadedFile() file: Express.Multer.File ): Promise<Express.Multer.File> {
    console.log('file', file);
    return file;
  }
}
