import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserInfoEntity } from './modules/users-information/entities/users-information.entity';
import { UserEntity } from './modules/users/entities/user.entity';
import { RoleEntity } from './modules/roles/entities/role.entity';
import { EmailVerificationEntity } from './modules/auth/entities/email-verification.entity';
import { PasswordResetEntity } from './modules/auth/entities/password-reset.entity';
import { UsersModule } from './modules/users/users.module';
import { UsersInformationModule } from './modules/users-information/users-information.module';
import { RolesModule } from './modules/roles/roles.module';
import { AuthModule } from './modules/auth/auth.module';

@Module({
  imports: [
    ConfigModule.forRoot(),
    TypeOrmModule.forRoot({
      type: 'mysql',
      host: process.env.DATABASE_HOST,
      port: +process.env.DATABASE_PORT,
      username: process.env.DATABASE_USERNAME,
      password: process.env.DATABASE_PASSWORD,
      database: process.env.DATABASE_NAME,
      entities: [
        UserEntity,
        UserInfoEntity,
        RoleEntity,
        EmailVerificationEntity,
        PasswordResetEntity
      ],
      synchronize: false,
      autoLoadEntities: true,
    }),
    UsersModule,
    UsersInformationModule,
    RolesModule,
    AuthModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
