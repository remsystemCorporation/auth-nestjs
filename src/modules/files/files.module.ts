import { Module } from '@nestjs/common';
import { FilesController } from './files.controller';
import { MulterModule } from '@nestjs/platform-express';
import { CloudinaryService } from './cloudinary.service';
import { UsersModule } from '../users/users.module';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    MulterModule.register({
      dest:'./uploads',
    }),
    ConfigModule,
    UsersModule,
    AuthModule
  ],
  controllers: [FilesController],
  providers: [CloudinaryService],
})
export class FilesModule {}
