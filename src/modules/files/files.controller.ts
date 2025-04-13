import {
  Controller,
  Post,
  UploadedFile,
  UseInterceptors,
  Req,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';
import { CloudinaryService } from './cloudinary.service';
import { UsersService } from '../users/users.service';
import { Auth } from '../auth/decorators/auth.decorator';
import { ValidRoles } from '../auth/interfaces/valid-roles.interface';
import { Request } from 'express';

@Controller('files')
export class FilesController {
  constructor(
    private readonly cloudinaryService: CloudinaryService,
    private readonly usersService: UsersService,
  ) { }

  @Post('upload-profile-picture')
  @Auth(ValidRoles.client, ValidRoles.Admin, ValidRoles.Super)
  @UseInterceptors(FileInterceptor('file'))
  async uploadProfilePicture(
    @UploadedFile() file: Express.Multer.File,
    @Req() req: Request,
  ) {
    const userId = req.user['idUser'];
    const imageUrl = await this.cloudinaryService.uploadImage(file, userId);
    return await this.usersService.updateProfilePicture(userId, imageUrl);
  }
}
