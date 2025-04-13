import { ConflictException, Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { UserEntity } from "src/modules/users/entities/user.entity";
import { UserInfoEntity } from "src/modules/users/entities/users-information.entity";
import { Repository } from "typeorm";
import { RegisterUserDto } from "../dto/register.dto";
import * as bcrypt from 'bcrypt';
import { TokenService } from "./token/token.service";
import { JwtPayload } from "../interfaces/jwt-payload.interface";
import { randomUUID } from "crypto";
import { MailService } from "src/modules/mail/mail.service";
import { UserVerificationEntity } from "../entities/user-verification.entity";
import { WhatsappService } from "src/modules/whatsapp/services/whatsapp.service";

@Injectable()
export class RegisterService {
    constructor(
        @InjectRepository(UserEntity)
        private readonly userRepository: Repository<UserEntity>,
        @InjectRepository(UserInfoEntity)
        private readonly userInfoRepository: Repository<UserInfoEntity>,

        private readonly mailService: MailService,
        private readonly tokenService: TokenService,
        private readonly whatsappService: WhatsappService
    ) { }

    async registerUser(registerUserDto: RegisterUserDto): Promise<string> {
        return this.userRepository.manager.transaction(async (manager) => {

            //destructuramos el objeto registerUserDto para obtener los valores de email y password
            const { email, password } = registerUserDto;
            //verificamos si el email ya existe en la base de datos
            const user = await manager.findOne(UserEntity, { where: { email } });
            if (user) throw new ConflictException('This email is already registered. Please log in or use the forgot password option.');

            //hash de la contraseña
            const hashedPassword = await bcrypt.hash(password, 10);

            //creamos la entidad de usuario y la guardamos en la base de datos
            const newUser = manager.create(UserEntity, {
                ...registerUserDto,
                password: hashedPassword,
                isActive: true,
                role: { idRol: 3 },
            });
            const userSaved = await manager.save(newUser);

            //creamos la entidad de UserInformation y la guardamos en la base de datos
            const userInfo = manager.create(UserInfoEntity, {
                user: userSaved,
                fullName: registerUserDto.fullName,
                company: registerUserDto.company,
                phone: registerUserDto.phone,
                address: registerUserDto.address,
                birthdate: registerUserDto.birthdate,
            });
            await manager.save(userInfo);

            //buscamos el rol del usuario para crear el token
            const userWithRole = await manager.findOne(UserEntity, {
                where: { idUser: userSaved.idUser },
                relations: { role: true },
            });

            //payload estandarizado para el token
            const payload: JwtPayload = {
                sub: userSaved.idUser,
                email: userSaved.email,
                rol: [userWithRole.role.rolName],
                jti: randomUUID(),
            };
            const token = await this.tokenService.generateToken(payload, '15m', process.env.JWT_EMAIL_SECRET);

            //guardamos el token en la tabla user_verification
            const userVerification = manager.create(UserVerificationEntity, {
                userId: { idUser: userSaved.idUser },
                verificationToken: token,
                verificationExpires: new Date(Date.now() + 15 * 60 * 1000), // 15 minutos
                method: 'email',
            });
            await manager.save(userVerification);

            const userInformation = await this.userInfoRepository.findOne({
                where: { user: { idUser: userSaved.idUser } }
            });
            
            const phoneNumber = userInformation?.phone;
            //enviamos el mensaje de whatsapp al usuario
            await this.whatsappService.notifyRegistration(userInfo.phone, userSaved.fullName, token);
            //enviamos el correo de verificacion al usuario
            await this.mailService.sendVerificationEmail(email, token);
            return 'We have sent a verification email to confirm your email address.';
        });
    }
}