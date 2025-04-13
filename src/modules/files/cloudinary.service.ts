// src/files/cloudinary.service.ts
import { Injectable } from '@nestjs/common';
import { v2 as cloudinary } from 'cloudinary';
import { ConfigService } from '@nestjs/config';
import { promises as fsPromises } from 'fs';

@Injectable()
export class CloudinaryService {
  constructor(private configService: ConfigService) {
    cloudinary.config({
      cloud_name: this.configService.get('CLOUDINARY_CLOUD_NAME'),
      api_key: this.configService.get('CLOUDINARY_API_KEY'),
      api_secret: this.configService.get('CLOUDINARY_API_SECRET'),
    });
  }

  async uploadImage(file: Express.Multer.File, userId: number|string): Promise<string> {
    const folder = `users/profile/${userId}`;

    const result = await cloudinary.uploader.upload(file.path,{
      folder
    });

    await fsPromises.unlink(file.path);
    return result.secure_url
  }
}
