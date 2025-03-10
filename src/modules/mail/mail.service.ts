import { Injectable } from '@nestjs/common';
import { ISendMailOptions, MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class MailService {
    constructor(private readonly mailerService: MailerService){}

     //You can add more methods to send different types of emails

    async sendMail(sendMailOptions: ISendMailOptions){
        await this.mailerService.sendMail(sendMailOptions);
    }
    // This method will be used to send the verification email
    async sendVerificationEmail(email: string, token: string){
        await this.sendMail({
            to: email,
            subject: 'Verificación de email',
            template: './verify-email',
            context: {
                token,
                frontendUrl:process.env.FRONTEND_URL
            }
        });
    }
    // This method will be used to send the password reset email
    async sendPasswordResetEmail(email: string, token: string){
        await this.sendMail({
            to:email,
            subject:'Restablecer la contraseña',
            template:'./reset-password',
            context:{
                token,
                frontendUrl:process.env.FRONTEND_URL
            }
        })
    }

    //You can add more methods to send different types of emails
}
