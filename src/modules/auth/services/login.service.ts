import { BadRequestException, ForbiddenException, Injectable, UnauthorizedException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { UserEntity } from "src/modules/users/entities/user.entity";
import { In, Repository } from "typeorm";
import { LoginUserDto } from "../dto/login.dto";
import * as bcrypt from 'bcrypt';
import { JwtPayload } from "../interfaces/jwt-payload.interface";
import { randomUUID } from "crypto";
import { JwtService } from "@nestjs/jwt";
import { RefreshTokenEntity } from "../entities/refresh_token.entity";
import { TokenService } from "./token/token.service";
import { UserValidationService } from "./shared/user-validation.service";
import { UserInfoEntity } from "src/modules/users/entities/users-information.entity";
import { WhatsappService } from "src/modules/whatsapp/services/whatsapp.service";


@Injectable()
export class LoginService {
    constructor(
        @InjectRepository(UserEntity)
        private readonly userRepository: Repository<UserEntity>,
        @InjectRepository(RefreshTokenEntity)
        private readonly refreshTokenRepository: Repository<RefreshTokenEntity>,
        @InjectRepository(UserInfoEntity)
        private readonly userInfoRepository: Repository<UserInfoEntity>,

        private readonly tokenService: TokenService,
        private readonly userValidationService: UserValidationService,
        private readonly whatsappService: WhatsappService
    ) { }

    async login(loginUserDto: LoginUserDto): Promise<{ accessToken: string, refreshToken: string }> {
        //desestructuramos el dto de login
        const { email, password } = loginUserDto;
        //validamos el usuario con el metodo de la clase userValidationService
        const user = await this.userValidationService.validateUser(email);

        //comparamos la contraseña con el hash de la base de datos
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) throw new BadRequestException('Email or password is incorrect');

        //estandar para generar todos los tokens de acceso y refresco
        const payload: JwtPayload = {
            sub: user.idUser,
            email: user.email,
            rol: [user.role.rolName],
            jti: randomUUID()
        }

        //creamos el token de acceso y refresco con el payload estandar
        const accessToken = await this.tokenService.generateToken(payload, '1h', process.env.JWT_SECRET);
        const refreshToken = await this.tokenService.generateToken(payload, '7d', process.env.JWT_REFRESH_TOKEN);

        //hasheamos el token de refresco para guardarlo en la base de datos
        const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

        //guardamos la informacion del token de refresco en la base de datos
        await this.refreshTokenRepository.save({
            userId: { idUser: user.idUser },
            token: hashedRefreshToken,
            jti: payload.jti,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 días
            revoked: false
        });

        //actualizamos la fecha de inicio de sesion del usuario
        user.lastLogin = new Date();
        await this.userRepository.save(user);
        const { password: _, ...adminWithoutPassword } = user;

        const userInfo = await this.userInfoRepository.findOne({
            where: { user: { idUser: user.idUser } }
        });
        const phoneNumber = userInfo?.phone;
        await this.whatsappService.notifyLogin(phoneNumber, user.fullName);

        return {
            ...adminWithoutPassword,
            accessToken,
            refreshToken
        }
    }
}