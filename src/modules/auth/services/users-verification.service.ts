import { MailService } from "src/modules/mail/mail.service";
import { TokenService } from "./token/token.service";
import { InjectRepository } from "@nestjs/typeorm";
import { UserEntity } from "src/modules/users/entities/user.entity";
import { MoreThan, Repository } from "typeorm";
import { UserValidationService } from "./shared/user-validation.service";
import { UserVerificationEntity } from "../entities/user-verification.entity";
import { BadRequestException, ConflictException, NotFoundException } from "@nestjs/common";
import { ResendMailDto } from "../dto/resend-email-verify.dto";
import { JwtPayload } from "../interfaces/jwt-payload.interface";

export class UserVerificationService {
    constructor(
        @InjectRepository(UserEntity)
        private readonly userRepository: Repository<UserEntity>,
        @InjectRepository(UserVerificationEntity)
        private readonly userVerificationRepository: Repository<UserVerificationEntity>,

        private readonly mailService: MailService,
        private readonly tokenService: TokenService,
        private readonly userValidationService: UserValidationService
    ) { }

    async verifyEmail(token: string): Promise<string> {
        // Verificar el token de verificación
        const payload = await this.tokenService.verifyToken(token, process.env.JWT_EMAIL_SECRET);

        const email = payload.email;
        // Verificar si el usuario existe y si ya está verificado
        const user = await this.userValidationService.checkUserExistsEmail(email);
        if (!user) throw new NotFoundException('User not found');
        if (user.isVerified) throw new ConflictException('User already verified');

        // Verificar si el token de verificación es válido y no ha expirado
        const userVerification = await this.userVerificationRepository.findOne({
            where: {
                userId: { idUser: user.idUser },
                verificationToken: token,
                verificationExpires: MoreThan(new Date())
            }
        });
        if (!userVerification) throw new BadRequestException('Invalid token');

        // Actualizar el estado del usuario a verificado
        userVerification.used = true;
        userVerification.verifiedAt = new Date();
        await this.userVerificationRepository.save(userVerification);

        // Actualizar el usuario a verificado
        user.isActive = true;
        user.isVerified = true;
        await this.userRepository.save(user);

        // eliminar el token de verificación esto es opcional
        //await this.userVerificationRepository.delete(userVerification.idVerification);
        return "Your email has been verified";
    }

    async resendVerificationEmail(resendMailDto: ResendMailDto): Promise<string> {
        return this.userRepository.manager.transaction(async (manager) => {

            //destructuramos el objeto resendMailDto para obtener los valores de email
            const { email } = resendMailDto;
            //validamos el usuario
            const user = await this.userValidationService.checkUserExistsEmail(email);
            if (!user) throw new NotFoundException('User not found');
            if (user.isVerified) throw new ConflictException('User already verified');

            //buscamos el token mas reciente de la tabla user_verification
            const existingToken = await manager.findOne(UserVerificationEntity, {
                where: { userId: { idUser: user.idUser } },
                order: { verificationExpires: 'DESC' },
            });

            // Si el usuario ya tiene un token activo, le damos el error para evitar el spam
            if (existingToken && existingToken.verificationExpires > new Date()) {
                throw new BadRequestException('A verification email has already been sent. Please check your inbox.');
            }

            // Si el usuario tiene un token ya enviado, lo eliminamos para crear uno nuevo
            await manager.delete(UserVerificationEntity,
                { userId: { idUser: user.idUser } },
            );

            // Generar un nuevo token de verificación
            const payload: JwtPayload = {
                sub: user.idUser,
                email: user.email,
                rol: [user.role.rolName]
            };

            const token = await this.tokenService.generateToken(payload, '15m', process.env.JWT_EMAIL_SECRET);

            const newVerification = manager.create(UserVerificationEntity, {
                userId: { idUser: user.idUser },
                verificationToken: token,
                verificationExpires: new Date(Date.now() + 15 * 60 * 1000), // 15 minutos
            });
            await manager.save(newVerification);
            await this.mailService.sendVerificationEmail(email, token);
            
            return "We have sent a verification email to confirm your email address.";
        })
    }
}