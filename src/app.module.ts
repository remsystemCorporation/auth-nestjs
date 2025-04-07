import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PasswordResetEntity } from './modules/auth/entities/password-reset.entity';
import { EmailVerificationEntity } from './modules/auth/entities/email-verification.entity';
import { UserEntity } from './modules/users/entities/user.entity';
import { UserInfoEntity } from './modules/users/entities/users-information.entity';
import { RoleEntity } from './modules/roles/entities/role.entity';
import { UsersModule } from './modules/users/users.module';
import { RolesModule } from './modules/roles/roles.module';
import { AuthModule } from './modules/auth/auth.module';
import { MailModule } from './modules/mail/mail.module';
import { RefreshTokenEntity } from './modules/auth/entities/refresh_token.entity';
import { FilesModule } from './modules/files/files.module';

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
        RoleEntity,
        UserInfoEntity,
        EmailVerificationEntity,
        PasswordResetEntity,
        RefreshTokenEntity
      ],
      synchronize: false,
      autoLoadEntities: true,
    }),
    UsersModule,
    RolesModule,
    AuthModule,
    MailModule,
    FilesModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
