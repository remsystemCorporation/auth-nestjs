import { BadRequestException, ConflictException, ForbiddenException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from '../users/entities/user.entity';
import { In, MoreThan, Repository } from 'typeorm';
import { RegisterUserDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UserInfoEntity } from '../users-information/entities/users-information.entity';
import { EmailVerificationEntity } from './entities/email-verification.entity';
import { PasswordResetEntity } from './entities/password-reset.entity';
import { LoginUserDto } from './dto/login.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResendMailDto } from './dto/resend-email-verify.dto';
import { MailService } from '../mail/mail.service';
import { UpdatePasswordDto } from './dto/reset-password.dto';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(UserEntity)
        private readonly userRepository: Repository<UserEntity>,
        @InjectRepository(UserInfoEntity)
        private readonly userInfoRepository: Repository<UserInfoEntity>,
        @InjectRepository(EmailVerificationEntity)
        private readonly emailVerificationRepository: Repository<EmailVerificationEntity>,
        @InjectRepository(PasswordResetEntity)
        private readonly passwordResetRepository: Repository<PasswordResetEntity>,

        private readonly jwtService: JwtService,
        private readonly mailService: MailService,
    ) { }

    async login(loginUserDto: LoginUserDto): Promise<{ accessToken: string }> {
        //destructuracion de datos
        const { email, password } = loginUserDto; 
        // 1. Verificar si el email existe
        const user = await this.userRepository.findOne({
            where: { email },
            relations:{
                userInformation:true,
                rol:true
            }});

        if (!user) throw new NotFoundException('email not found');
        if (!user.is_active) throw new ForbiddenException('Your account has been suspended. Contact support.');
        if (user.deleted_at) throw new ForbiddenException('Your account is in the process of being deleted.');
        if (!user.is_verified) throw new UnauthorizedException('You must verify your email before logging in.');

        // 2. Verificar si la contraseña es correcta
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) throw new BadRequestException('Invalid password');

        // 3. Generar un token de acceso
        const payload = {email: user.email, id: user.id_user, rol: user.rol};
        const accessToken = this.jwtService.sign(payload);

        user.last_login = new Date();
        await this.userRepository.save(user);

        // 4. Retornar el token de acceso y omitir la contraseña
        const {password: _password, ...adminWithoutPassword} = user;
        return{...adminWithoutPassword, accessToken};
    }

    async register(registerUserDto: RegisterUserDto): Promise<string>{
        return this.userRepository.manager.transaction( async (manager)=>{
             // 1. Validar si el email ya existe
            const { email, password } = registerUserDto;
            const existEmail = await this.userRepository.findOne({where: {email}});
            if(existEmail) throw new ConflictException('Email already exist');

            // 2. Hashear la contraseña y crear un token de verificación
            const hashedPassword = await bcrypt.hash(password, 10);
            const token = this.jwtService.sign(
                {email},
                {expiresIn: '15m'}
            );
            
            // 3. Crear y guardar el nuevo usuario con la informacion en la tabla
            //informacion de usuario
            const newUser = manager.create(UserEntity,{
                ...registerUserDto,
                password: hashedPassword,
                is_active: true,
                rol:{id_rol:3}
            });
            const user = await manager.save(newUser);

            // 4. Crear y guardar la información del usuario
            const newUserInformation = manager.create(UserInfoEntity,{
                user,
                full_name: user.full_name
            });
            await manager.save(newUserInformation);

            // 5. Crear y guardar el token de verificación de email
            const emailVerification  = manager.create(EmailVerificationEntity,{
                user_id: user.id_user,
                verification_token: token,
                verification_expires: new Date(Date.now() + 15 * 60 * 1000)
            });
            await manager.save(EmailVerificationEntity, emailVerification );

            // 6. Enviar el email de verificación
            await this.mailService.sendVerificationEmail(email, token);
            
            // 7. Retornar un mensaje
            return "We have sent a verification email to confirm your email address.";
        });
    }

    async verifyEmail(token: string): Promise<string>{
        // 1. Verificar si el token es válido
        let payload;
        try{
            payload = this.jwtService.verify(token);
        } catch (error){
            if(error == 'jwt expired'){
                throw new ConflictException('Token has expired');
            }
            
            throw new ConflictException('Invalid token');
        }
        const email = payload.email;

        // 2. Verificar si el usuario existe
        const user  = await this.userRepository.findOne({where:{email}});
        if(!user) throw new NotFoundException('User not found');

        // 3. Verificar si el usuario ya ha sido verificado
        if (user.is_verified) throw new ConflictException('User already verified');

        // 4. Verificar si el token de verificación es válido
        const emailVerification = await this.emailVerificationRepository.findOne({
            where:{
                user_id: user.id_user,
                verification_token: token,
                verification_expires: MoreThan(new Date())
            }
        });

        if(!emailVerification) throw new BadRequestException('Invalid token');

        // 5. Actualizar el estado del usuario
        user.is_active = true;
        user.is_verified = true;
        await this.userRepository.save(user);

        // 6.eliminar el token de verificación
        await this.emailVerificationRepository.delete(emailVerification.id_verification);

        return "Your email has been verified";
    }

    async resendVerificationEmail(resendMailDto:ResendMailDto): Promise<string>{
        return this.userRepository.manager.transaction(async (manager)=>{
            // 1. Verificar si el email existe
            const {email} = resendMailDto;
            const user = await manager.findOne(UserEntity, {where:{email}});
            if(!user) throw new NotFoundException('User not found');
        
            // 2. Verificar si el usuario ya ha sido verificado
            if(user.is_verified) throw new ConflictException('User already verified');

            // 3. Verificar si ya existe un token activo, si no eliminarlo
            const existingToken = await manager.findOne(EmailVerificationEntity,{
                where:{user_id: user.id_user},
                order:{verification_expires:'DESC'}
            });

            if(existingToken && existingToken.verification_expires > new Date()) {
                throw new ConflictException('A verification email has already been sent. Please check your inbox.');
            }
            await manager.delete(EmailVerificationEntity, {user_id: user.id_user});

            // 4. Crear y guardar el token de verificación de email
            const token = this.jwtService.sign(
                {email},
                {
                    secret: process.env.JWT_SECRET,
                    expiresIn: '15m'
                }
            );
            const emailVerification = manager.create(EmailVerificationEntity,{
                user_id: user.id_user,
                verification_token: token,
                verification_expires: new Date(Date.now() + 15*60*1000)
            });
            await manager.save(EmailVerificationEntity, emailVerification);

            // 5. Enviar el email de verificación
            await this.mailService.sendVerificationEmail(email, token);

            return "We have sent a verification email to confirm your email address.";
        })
    }

    async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<string> {
        return this.userRepository.manager.transaction(async (manager) => {
            const { email } = forgotPasswordDto;
            const user = await manager.findOne(UserEntity, { where: { email } });
            if (!user) throw new NotFoundException('User not found');
    
            let resetRecord = await manager.findOne(PasswordResetEntity, {
                where: { user_id: user.id_user },
                order: { reset_password_expires: 'DESC' }
            });
    
            // Si el usuario ya tiene un bloqueo activo
            if (resetRecord?.reset_password_block_until && resetRecord.reset_password_block_until > new Date()) {
                throw new ConflictException(`You have exceeded the reset attempts. Try again after ${resetRecord.reset_password_block_until}`);
            }
    
            let resetCount = resetRecord ? resetRecord.password_reset_count : 0;
            resetCount++;
    
            let blockUntil: Date | null = null;
            if (resetCount >= 5) {
                blockUntil = new Date();
                blockUntil.setHours(blockUntil.getHours() + 24); // Bloqueo por 24 horas
            }
    
            const token = this.jwtService.sign(
                { email },
                { expiresIn: '15m', secret: process.env.JWT_SECRET }
            );
    
            const emailResetRecord = manager.create(PasswordResetEntity, {
                user_id: user.id_user,
                reset_password_token: token,
                reset_password_expires: new Date(Date.now() + 15 * 60 * 1000),
                password_reset_count: resetCount,
                reset_password_block_until: blockUntil
            });
    
            await manager.save(PasswordResetEntity, emailResetRecord);
    
            // Solo enviamos el correo si el usuario aún no ha alcanzado el límite
            if (!blockUntil) {
                await this.mailService.sendPasswordResetEmail(email, token);
    
                return 'We have sent a password reset email address.';
            }
    
            return `You have exceeded the reset attempts. Try again after ${blockUntil}`;
        });
    }

    async updatePasswords(token: string, resetPasswordDto: UpdatePasswordDto): Promise<string>{
        return this.userRepository.manager.transaction(async(manager)=>{
            let payload;
            try {
                payload= this.jwtService.verify(token);
            } catch (error) {
                if(error == 'jwt expired'){
                    throw new ConflictException('Token has expired');
                }

                throw new ConflictException('Invalid token');
            }
            const email = payload.email;

            const user = await manager.findOne(UserEntity, {where:{email}});
            if(!user) throw new NotFoundException('User not found');

            const {password, newPassword, confirmPassword} = resetPasswordDto;
            const  validatePassword = await bcrypt.compare(password, user.password);
            if(!validatePassword) throw new BadRequestException('Invalid password');

            if(newPassword !== confirmPassword) throw new BadRequestException('New password and confirmation do not match');
            if(password == newPassword) throw new BadRequestException('New password cannot be the same as the current password');

            const hashedNewPassword = await bcrypt.hash(newPassword,10);
            user.password = hashedNewPassword;
            await manager.save(user);

            return "Your password has been updated successfully";
        });
    }

    async getProfile(id: number): Promise<UserEntity>{      
        const user = await this.userRepository.findOne({
            where:{id_user:id},
            relations:{
                userInformation:true,
                rol:true
            }
        });
        if (!user) throw new NotFoundException('User not found');
        return user;
    }
}
