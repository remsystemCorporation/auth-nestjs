import { MailerModule } from '@nestjs-modules/mailer';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { join } from 'path';
import { MailService } from './mail.service';

@Module({
  imports: [
    MailerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        transport: {
          host: config.get('MAIL_HOST'),
          port: config.get('MAIL_PORT'),
          secure: false,
          auth: {
            user: config.get('MAIL_USER'),
            pass: config.get('MAIL_PASSWORD'),
          },
        },
        defaults: {
          from: `"team-support" <${config.get('MAIL_FROM')}>`,
        },
        template: {
            dir: process.env.NODE_ENV === 'production' 
              ? join(__dirname, './templates') 
              : join(process.cwd(), 'src/modules/mail/templates'),
            adapter: new (require('@nestjs-modules/mailer/dist/adapters/handlebars.adapter')).HandlebarsAdapter(),
            options: {
              strict: true,
            },
          }
      }),
    }),
  ],
  exports: [MailerModule],
  providers: [MailService],
})
export class MailModule {}
