import { Module } from '@nestjs/common';
import { UsersInformationService } from './users-information.service';
import { UsersInformationController } from './users-information.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserInfoEntity } from './entities/users-information.entity';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports:[TypeOrmModule.forFeature([UserInfoEntity]),
  AuthModule,
  ],
  controllers: [UsersInformationController],
  providers: [UsersInformationService],
  exports:[TypeOrmModule]
})
export class UsersInformationModule {}
