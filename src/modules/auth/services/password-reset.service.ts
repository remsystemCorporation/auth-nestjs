import { BadRequestException, ConflictException, Injectable, NotFoundException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { PasswordResetEntity } from "../entities/password-reset.entity";
import { UserEntity } from "src/modules/users/entities/user.entity";
import { ForgotPasswordDto } from "../dto/forgot-password.dto";
import { EntityManager, Repository } from "typeorm";
import { UserValidationService } from "./shared/user-validation.service";
import { TokenService } from "./token/token.service";
import { JwtPayload } from "../interfaces/jwt-payload.interface";
import { randomUUID } from "crypto";
import { MailService } from "src/modules/mail/mail.service";
import { UpdatePasswordDto } from "../dto/reset-password.dto";
import * as bcrypt from "bcrypt";

@Injectable()
export class PasswordResetService {
    constructor(
        @InjectRepository(PasswordResetEntity)
        private readonly passwordResetRepository: Repository<PasswordResetEntity>,

        @InjectRepository(UserEntity)
        private readonly userRepository: Repository<UserEntity>,

        private readonly userValidationService: UserValidationService,
        private readonly tokenService: TokenService,
        private readonly mailService: MailService
    ) { }

    async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<string> {
        return this.userRepository.manager.transaction(async (manager) => {
            //verificar si el email existe
            const { email } = forgotPasswordDto;
            const user = await this.userValidationService.checkUserExistsEmail(email);

            //listamos los registros de la tabla password_reset para ver el mas reciente
            let resetRecord = await manager.findOne(PasswordResetEntity, {
                where: { userId: { idUser: user.idUser } },
                order: { resetExpires: 'DESC' }
            });

            // Si el usuario ya tiene un bloqueo por muchos intentos le damos el error
            if (resetRecord?.resetBlockUntil && resetRecord.resetBlockUntil > new Date()) {
                throw new ConflictException(`You have exceeded the reset attempts. Try again after ${resetRecord.resetBlockUntil}`);
            }

            //Verificar si ya existe un token activo o si acaba de realizar una peticion
            //la peticion se puede hacer cada 15 minutos
            if (resetRecord && resetRecord.resetExpires > new Date()) {
                throw new ConflictException('A password reset email has already been sent. Please check your inbox.');
            }

            // si no hay bloqueo se toma el valor resetCount y se incrementa
            let resetCount = resetRecord ? resetRecord.resetCount : 0;
            resetCount++;

            // Si el usuario ha excedido el límite de intentos, se bloquea por 24 horas
            //por defecto el bloqueo se da por 5 intentos
            let blockUntil: Date | null = null;
            if (resetCount >= 5) {
                blockUntil = new Date();
                blockUntil.setHours(blockUntil.getHours() + 24); // Bloqueo por 24 horas o 1 día
            }

            //generar token con una duracion de 15 minutos, supongo que sufinete para cambiar la contraseña
            const payload: JwtPayload = {
                sub: user.idUser,
                email: user.email,
                rol: [user.role.rolName],
                jti: randomUUID(),
            };
            const token = await this.tokenService.generateToken(payload, '15m', process.env.JWT_PASSWORD_SECRET);

            //guardamos el registro en la tabla password_reset
            const emailResetRecord = manager.create(PasswordResetEntity, {
                userId: { idUser: user.idUser },
                resetToken: token,
                resetExpires: new Date(Date.now() + 15 * 60 * 1000),
                resetCount: resetCount,
                resetBlockUntil: blockUntil,
                isUsed: false,
                revoked: false,
            });
            await manager.save(emailResetRecord);

            // Solo enviamos el correo si el usuario aún no ha alcanzado el límite
            if (!blockUntil) {
                await this.mailService.sendPasswordResetEmail(email, token);

                return 'We have sent a password reset email address.';
            }
            return `You have exceeded the reset attempts.`;
        });
    }

    async resetPassword(token: string, resetPasswordDto: UpdatePasswordDto): Promise<string> {
        return this.userRepository.manager.transaction(async (manager) => {

            const payload = await this.tokenService.verifyToken(token, process.env.JWT_PASSWORD_SECRET);

            const email = payload.email;
            const user = await this.userValidationService.checkUserExistsEmail(email);
            if (!user) throw new ConflictException('User not found');

            const resetRecord = await manager.findOne(PasswordResetEntity, {
                where: { userId: { idUser: user.idUser }, resetToken: token },
            });

            if (!resetRecord) throw new ConflictException('Invalid or expired reset token');
            if (resetRecord.isUsed) throw new ConflictException('This token has alredy been used');
            if (resetRecord.revoked) throw new ConflictException('This token has been revoked');
            if (resetRecord.resetExpires < new Date()) throw new ConflictException('Token has expired');

            const { newPassword, confirmPassword } = resetPasswordDto;
            if (newPassword !== confirmPassword) throw new BadRequestException('New password and confirmation do not match');

            const hashedNewPassword = await bcrypt.hash(newPassword, 10);
            user.password = hashedNewPassword;
            await manager.save(user);

            resetRecord.isUsed = true;
            resetRecord.revoked = null;
            await manager.save(resetRecord);

            return 'Password reset successfully';
        });
    }

}