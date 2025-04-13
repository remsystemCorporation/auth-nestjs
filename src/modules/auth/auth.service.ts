/* import { BadRequestException, ConflictException, ForbiddenException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from '../users/entities/user.entity';
import { In, MoreThan, Repository } from 'typeorm';
import { RegisterUserDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { JsonWebTokenError, JwtService, NotBeforeError, TokenExpiredError } from '@nestjs/jwt';

import { PasswordResetEntity } from './entities/password-reset.entity';
import { LoginUserDto } from './dto/login.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResendMailDto } from './dto/resend-email-verify.dto';
import { UpdatePasswordDto } from './dto/reset-password.dto';
import { UserInfoEntity } from '../users/entities/users-information.entity';
import { MailService } from '../mail/mail.service';
import { RefreshTokenEntity } from './entities/refresh_token.entity';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { randomUUID } from 'crypto';
import { UserVerificationEntity } from './entities/user-verification.entity';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(UserEntity)
        private readonly userRepository: Repository<UserEntity>,
        @InjectRepository(UserInfoEntity)
        private readonly userInfoRepository: Repository<UserInfoEntity>,
        @InjectRepository(UserVerificationEntity)
        private readonly userVerificationRepository: Repository<UserVerificationEntity>,
        @InjectRepository(PasswordResetEntity)
        private readonly passwordResetRepository: Repository<PasswordResetEntity>,
        @InjectRepository(RefreshTokenEntity)
        private readonly refreshTokenResetRepository: Repository<RefreshTokenEntity>,

        private readonly jwtService: JwtService,
        private readonly mailService: MailService,
    ) { }

     async login(loginUserDto: LoginUserDto): Promise<{ accessToken: string, refreshToken: string }> {
        // 1. Validar el usuario
        const { email, password } = loginUserDto;
        const user = await this.validateUser(email);

        // 2. Verificar contraseña
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) throw new BadRequestException('Invalid credentials');

        // 4. Generar tokens
        const payload: JwtPayload = {
            sub: user.idUser,
            email: user.email,
            rol: [user.role.rolName],
            jti: randomUUID(),
        };

        const accessToken = this.generateToken(payload, '1h', process.env.JWT_SECRET);
        const refreshToken = this.generateToken(payload, '7d', process.env.JWT_REFRESH_TOKEN);

        //hash
        const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

        // 5. Guardar refresh token hasheado
        await this.refreshTokenResetRepository.save({
            userId: { idUser: user.idUser },
            token: hashedRefreshToken,
            jti: payload.jti,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 días
            revoked: false
        });

        // 6. Actualizar último login
        user.lastLogin = new Date();
        await this.userRepository.save(user);

        // 7. Retornar datos (sin password)
        const { password: _password, ...adminWithoutPassword } = user;
        return {
            ...adminWithoutPassword,
            accessToken,
            refreshToken,
        };
    }

    async register(registerUserDto: RegisterUserDto): Promise<string> {
        return this.userRepository.manager.transaction(async (manager) => {
            // 1. Validar si el email ya existe
            const { email, password } = registerUserDto;
            const existEmail = await this.userRepository.findOne({ where: { email } });
            if (existEmail) throw new ConflictException('This email is already registered. Please log in or use the forgot password option.');

            // 2. Hashear la contraseña y crear un tokenEmail de verificación
            const hashedPassword = await bcrypt.hash(password, 10);
            const token = this.jwtService.sign(
                { email },
                { expiresIn: '15m', secret: process.env.JWT_EMAIL_SECRET }
            );

            // 3. Crear y guardar el nuevo usuario con la informacion en la tabla
            //informacion de usuario
            const newUser = manager.create(UserEntity, {
                ...registerUserDto,
                password: hashedPassword,
                isActive: true,
                //el rol puede cambiar, puedes optar por  otra forma o usar solo una tabla unificada para informacion y usuario :)
                role: { idRol: 3 }
            });
            const user = await manager.save(newUser);

            // 4. Crear y guardar la información del usuario
            const newUserInformation = manager.create(UserInfoEntity, {
                user,
                fullName: registerUserDto.fullName,
                company: registerUserDto.company,
                phone: registerUserDto.phone,
                address: registerUserDto.address,
                birthdate: registerUserDto.birthdate,
            });
            await manager.save(newUserInformation);

            // 5. Crear y guardar el token de verificación de email
            const userVerification = manager.create(UserVerificationEntity, {
                userId: user,
                verificationToken: token,
                verificationExpires: new Date(Date.now() + 15 * 60 * 1000),
                method: 'email',
            });
            await manager.save(userVerification);

            // 6. Enviar el email de verificación
            await this.mailService.sendVerificationEmail(email, token);

            // 7. Retornar un mensaje
            return "We have sent a verification email to confirm your email address.";
        });
    } 

     async verifyEmail(token: string): Promise<string> {
        // 1. Verificar si el token es válido
        const payload = this.validateEmailToken(token);
        const email = payload.email;

        // 2. Verificar si el usuario existe
        const user = await this.userRepository.findOne({ where: { email } });
        if (!user) throw new NotFoundException('User not found');

        // 3. Verificar si el usuario ya ha sido verificado
        if (user.isVerified) throw new ConflictException('User already verified');

        // 4. Verificar si el token de verificación es válido
        const userVerification = await this.userVerificationRepository.findOne({
            where: {
                userId: { idUser: user.idUser },
                verificationToken: token,
                verificationExpires: MoreThan(new Date())
            }
        });

        if (!userVerification) throw new BadRequestException('Invalid token');

        // 5. Actualizar el estado del usuario
        userVerification.used = true;
        userVerification.verifiedAt = new Date();
        await this.userVerificationRepository.save(userVerification);

        user.isActive = true;
        user.isVerified = true;
        await this.userRepository.save(user);

        // 6.eliminar el token de verificación
        //await this.userVerificationRepository.delete(userVerification.idVerification);
        return "Your email has been verified";
    }
 
    async resendVerificationEmail(resendMailDto: ResendMailDto): Promise<string> {
        return this.userRepository.manager.transaction(async (manager) => {
            // 1. Verificar si el email existe
            const { email } = resendMailDto;
            const user = await manager.findOne(UserEntity, { where: { email } });
            if (!user) throw new NotFoundException('User not found');

            // 2. Verificar si el usuario ya ha sido verificado
            if (user.isVerified) throw new ConflictException('User already verified');

            // 3. Verificar si ya existe un token activo o si acaba de realizar una peticion, si no eliminarlo
            const existingToken = await manager.findOne(UserVerificationEntity, {
                where: { userId: { idUser: user.idUser } },
                order: { verificationExpires: 'DESC' }
            });

            if (existingToken && existingToken.verificationExpires > new Date()) {
                throw new ConflictException('A verification email has already been sent. Please check your inbox.');
            }
            await manager.delete(UserVerificationEntity,
                { userId: { idUser: user.idUser } }
            );

            // 4. Crear y guardar el token de verificación de email
            const token = this.jwtService.sign(
                { email },
                {
                    secret: process.env.JWT_EMAIL_SECRET,
                    expiresIn: '15m'
                }
            );
            const userVerification = manager.create(UserVerificationEntity, {
                userId: { idUser: user.idUser },
                verificationToken: token,
                verificationExpires: new Date(Date.now() + 15 * 60 * 1000)
            });
            await manager.save(userVerification);

            // 5. Enviar el email de verificación
            await this.mailService.sendVerificationEmail(email, token);

            return "We have sent a verification email to confirm your email address.";
        })
    } 
    async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<string> {
        return this.userRepository.manager.transaction(async (manager) => {
            //1. verificar si el email existe
            const { email } = forgotPasswordDto;
            const user = await manager.findOne(UserEntity, { where: { email } });
            if (!user) throw new NotFoundException('User not found');
            //cosas que tambien considero, si el usuario ya esta verificado y activo
            //no tiene sentido enviarle un correo para resetear la contraseña
            if (!user.isActive) throw new ConflictException('user not active');
            if (!user.isVerified) throw new ConflictException('user not verified');


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
            const token = this.jwtService.sign({ email }, { expiresIn: '15m', secret: process.env.JWT_PASSWORD_SECRET });

            //guardamos el registro en la tabla password_reset
            const emailResetRecord = manager.create(PasswordResetEntity, {
                userId: { idUser: user.idUser },
                resetPasswordToken: token,
                resetPasswordExpires: new Date(Date.now() + 15 * 60 * 1000),
                passwordResetCount: resetCount,
                resetPasswordBlockUntil: blockUntil
            });
            await manager.save(emailResetRecord);

            // Solo enviamos el correo si el usuario aún no ha alcanzado el límite
            if (!blockUntil) {
                await this.mailService.sendPasswordResetEmail(email, token);

                return 'We have sent a password reset email address.';
            }

            return `You have exceeded the reset attempts. Try again after ${blockUntil}`;
        });
    }

    async resetPassword(token: string, resetPasswordDto: UpdatePasswordDto): Promise<string> {
        return this.userRepository.manager.transaction(async (manager) => {
            //PRIMERO VALIDAMOS EL TOKEN
            const payload = this.validatePasswordToken(token);

            //EXTRAEMOS EL EMAIL DEL PAYLOAD Y BUSCAMOS EL USUARIO
            const email = payload.email;
            const user = await manager.findOne(UserEntity, { where: { email } });
            if (!user) throw new NotFoundException('User not found');

            //BUSCAMOS EL TOKEN EN LA TABLA PASSWORD_RESET
            const resetRecord = await manager.findOne(PasswordResetEntity, {
                where: { userId: { idUser: user.idUser }, resetToken: token },
            });
            //validamos varios aspectos
            if (!resetRecord) throw new ConflictException('Invalid or expired reset token');
            if (resetRecord.isUsed) throw new ConflictException('This token has alredy been used');
            if (resetRecord.revoked) throw new ConflictException('This token has been revoked');
            if (resetRecord.resetExpires < new Date()) throw new ConflictException('Token has expired');

            //actualizar contraseña
            //DESCTRUCTURAMOS LOS DATOS DEL DTO
            const { newPassword, confirmPassword } = resetPasswordDto;
            //validamos sentencias necesarias
            if (newPassword !== confirmPassword) throw new BadRequestException('New password and confirmation do not match');

            //si todo es correcto, actualizamos la contraseña
            const hashedNewPassword = await bcrypt.hash(newPassword, 10);
            user.password = hashedNewPassword;
            await manager.save(user);

            //marcamos el token como usado y actualizamos el registro para evitar reutilizacion
            //de tokens o mas problemas de seguridad
            resetRecord.isUsed = true;
            resetRecord.revoked = null;
            await manager.save(resetRecord);

            return "Your password has been updated successfully";
        });
    }
 
    async refreshToken(refreshToken: string): Promise<{ accessToken: string, refreshToken: string }> {
        // 1. Verificar firma JWT
        const payload = this.validateRefreshToken(refreshToken); // Decodificamos y verificamos la firma del JWT

        // 2. Obtener el usuario
        const user = await this.userRepository.findOne({
            where: { idUser: payload.sub },
            relations: { role: true },
            select: ['idUser', 'email', 'isActive', 'isVerified', 'deletedAt']
        });

        if (!user || !user.isActive || user.deletedAt || !user.isVerified) {
            throw new ForbiddenException('Access Denied');
        }

        // 3. Obtener el último refresh token válido del usuario con el mismo jti
        const storedToken = await this.refreshTokenResetRepository.findOne({
            where: { jti: payload.jti, userId: { idUser: user.idUser } },
            order: { createdAt: 'DESC' } // Asegurarse de obtener el último token
        });

        if (!storedToken) throw new UnauthorizedException('Session not found'); // Si no encontramos el token, significa que es inválido

        // 4. Comparar jti y validar el refresh token
        if (storedToken.jti !== payload.jti) {
            throw new ForbiddenException('Invalid or reused refresh token');
        }

        // Comparar el refreshToken hasheado almacenado en la base de datos con el token recibido
        const isTokenValid = await bcrypt.compare(refreshToken, storedToken.token);
        if (!isTokenValid || storedToken.revoked || storedToken.expiresAt < new Date()) {
            throw new ForbiddenException('Access Denied');
        }

        // 5. Revocar el refresh token anterior
        storedToken.revoked = true; // Marcamos el token anterior como revocado
        await this.refreshTokenResetRepository.save(storedToken); // Guardamos la actualización

        // 6. Generar nuevos tokens
        const newPayload: JwtPayload = {
            sub: user.idUser,
            email: user.email,
            rol: [user.role.rolName],
            jti: randomUUID(),
        };

        const newAccessToken = this.generateToken(newPayload, '1h', process.env.JWT_SECRET);
        const newRefreshToken = this.generateToken(newPayload, '7d', process.env.JWT_REFRESH_TOKEN);

        // Hashear el nuevo refresh token y guardarlo en la base de datos
        const hashedNewRefreshToken = await bcrypt.hash(newRefreshToken, 10);

        // Guardar nuevo refresh token
        await this.refreshTokenResetRepository.save({
            userId: { idUser: user.idUser },
            token: hashedNewRefreshToken,
            jti: newPayload.jti, // Guardar el nuevo jti
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 días
            revoked: false, // El nuevo token no está revocado
        });

        // 7. Retornar los nuevos tokens
        return {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        };
    }

    async logout(userId: number, refreshToken: string): Promise<void> {
        // 1. Verificar la validez del token
        const payload = this.validateRefreshToken(refreshToken);

        if (payload.sub !== userId) {
            throw new ForbiddenException('User ID does not match the token');
        }

        
        // 2. Obtener el usuario
        const user = await this.userRepository.findOne({
            where:{idUser: payload.sub},
            relations: { role: true }, 
            select: ['idUser', 'email', 'isActive', 'isVerified', 'deletedAt']
        });
        
        if (!user || !user.isActive || user.deletedAt || !user.isVerified) {
            throw new ForbiddenException('Access Denied');
        }
        // 3. Obtener el último refresh token válido del usuario con el mismo jti
        const storedToken = await this.refreshTokenResetRepository.findOne({
            where: { jti: payload.jti, userId: { idUser: user.idUser } },
            order: { createdAt: 'DESC' }
        });

        if (!storedToken) throw new UnauthorizedException('Session not found');

        // 4. Comparar jti y validar el refresh token
        if (storedToken.jti !== payload.jti) {
            throw new ForbiddenException('Invalid or reused refresh token');
        }

        // Comparar el refreshToken hasheado almacenado en la base de datos con el token recibido
        const isTokenValid = await bcrypt.compare(refreshToken, storedToken.token);
        if (!isTokenValid || storedToken.revoked || storedToken.expiresAt < new Date()) {
            throw new ForbiddenException('Access Denied');
        }

        // 5. Revocar el refresh token
        storedToken.revoked = true; // Marcamos el token como revocado
        await this.refreshTokenResetRepository.save(storedToken);
        return;
    }



    //---------------metodos private-----------------------//
    async validateUser(email: string): Promise<UserEntity> {
        const user = await this.userRepository.findOne({
            where: { email },
            relations: { role: true },
            select: ['idUser', 'email', 'password', 'profilePicture' ,'isActive', 'isVerified', 'deletedAt']
        });
        if (!user) throw new NotFoundException('Email not found');
        if (!user.isActive) throw new ForbiddenException('Account suspended. Contact support.');
        if (user.deletedAt) throw new ForbiddenException('Account pending deletion.');
        if (!user.isVerified) throw new UnauthorizedException('Email verification required.');

        return user;
    }

    //metodo para generar tokens, se puede usar para el refresh token y el email token
    private generateToken(payload: JwtPayload, expiresIn: string, secretKey: string, email?: string): string {
        return this.jwtService.sign(payload, {
            expiresIn,
            secret: secretKey
        });
    }

    //metodo para validar el token de refresco
    private validateRefreshToken(refreshToken: string): JwtPayload {
        try {
            const payload = this.jwtService.verify(refreshToken, {
                secret: process.env.JWT_REFRESH_TOKEN,
            });
            return payload;
        } catch (error) {
            if (error instanceof TokenExpiredError) {
                throw new UnauthorizedException('Refresh token expired');
            } else if (error instanceof JsonWebTokenError) {
                throw new UnauthorizedException('Invalid refresh token');
            } else if (error instanceof NotBeforeError) {
                throw new ForbiddenException('Token not active yet');
            } else {
                console.error('Unknown error verifying refresh token:', error);
                throw new UnauthorizedException('Could not validate refresh token');
            }
        }
    }

    //metodo para validar el token de verificacion del email
    private validateEmailToken(token: string): JwtPayload {
        try {
            const payload = this.jwtService.verify(token, {
                secret: process.env.JWT_EMAIL_SECRET,
            });
            return payload;
        } catch (error) {
            if (error instanceof TokenExpiredError) {
                throw new UnauthorizedException('Refresh token expired');
            } else if (error instanceof JsonWebTokenError) {
                throw new UnauthorizedException('Invalid refresh token');
            } else if (error instanceof NotBeforeError) {
                throw new ForbiddenException('Token not active yet');
            } else {
                console.error('Unknown error verifying refresh token:', error);
                throw new UnauthorizedException('Could not validate refresh token');
            }
        }
    }

    //metodo para validar el token de contraseña
    private validatePasswordToken(token: string): JwtPayload {
        try {
            const payload = this.jwtService.verify(token, {
                secret: process.env.JWT_PASSWORD_SECRET,
            });
            return payload;
        } catch (error) {
            if (error instanceof TokenExpiredError) {
                throw new UnauthorizedException('Refresh token expired');
            } else if (error instanceof JsonWebTokenError) {
                throw new UnauthorizedException('Invalid refresh token');
            } else if (error instanceof NotBeforeError) {
                throw new ForbiddenException('Token not active yet');
            } else {
                console.error('Unknown error verifying refresh token:', error);
                throw new UnauthorizedException('Could not validate refresh token');
            }
        }
    }

}
 */