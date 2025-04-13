import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from '../users/entities/user.entity';
import { AuthController } from './auth.controller';
//import { AuthService } from './auth.service';
import { PasswordResetEntity } from './entities/password-reset.entity';
import { UserInfoEntity } from '../users/entities/users-information.entity';
import { JwtStrategy } from './strategy/jwt.strategy';
import { MailModule } from '../mail/mail.module';
import { MailService } from '../mail/mail.service';
import { RefreshTokenEntity } from './entities/refresh_token.entity';
import { UserVerificationEntity } from './entities/user-verification.entity';
import { LoginService } from './services/login.service';
import { RegisterService } from './services/register.service';
import { TokenService } from './services/token/token.service';
import { UserValidationService } from './services/shared/user-validation.service';
import { PasswordResetService } from './services/password-reset.service';
import { UserVerificationService } from './services/users-verification.service';
import { AuthTokenService } from './services/auth-token.service';
import { WhatsappService } from '../whatsapp/services/whatsapp.service';



@Module({
  imports: [
    TypeOrmModule.forFeature([UserEntity, UserInfoEntity, UserVerificationEntity, PasswordResetEntity, RefreshTokenEntity]),
    MailModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: () => {
        return {
          secret: process.env.JWT_SECRET,
          signOptions: {
            expiresIn: '1h',
          },
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [
    //AuthService,
    JwtStrategy,
    MailService,
    LoginService,
    RegisterService,
    UserVerificationService,
    TokenService,
    UserValidationService,
    PasswordResetService,
    AuthTokenService,
    WhatsappService 
    
  ],
  exports: [
    TypeOrmModule,
    PassportModule,
    JwtStrategy,
    PassportModule,
    JwtModule
  ],
})
export class AuthModule { }
