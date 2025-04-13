import { Injectable, Logger, OnModuleInit } from "@nestjs/common";
import { Client, LocalAuth } from "whatsapp-web.js";
import * as qrcode from 'qrcode-terminal';
import * as path from 'path';

@Injectable()
export class WhatsappService implements OnModuleInit {

    private client: Client;
    private readonly logger = new Logger(WhatsappService.name);

    onModuleInit() {
        this.client = new Client({
            authStrategy: new LocalAuth({
                 dataPath: path.join(__dirname, '..', 'session')
            }),
            puppeteer: {
                headless: true,
                args: ['--no-sandbox', '--disable-setuid-sandbox'],
            },
        });

        this.client.on('qr', (qr) => {
            qrcode.generate(qr, { small: true });
            this.logger.log('QR Code generated, scan it with WhatsApp.');
        });

        this.client.on('ready', () => {
            this.logger.log('WhatsApp client is ready!');
        });

        this.client.on('message', (message) => {
            this.logger.log(`Received message: ${message.body}`);
        });

        this.client.initialize();
    }

    async sendMessage(phoneNumber: string, message: string): Promise<void> {
        try {
            const chatId = `${phoneNumber}@c.us`; // Formato estándar de WhatsApp
            await this.client.sendMessage(chatId, message);
        } catch (error) {
            this.logger.error(`Error enviando mensaje a ${phoneNumber}: ${error.message}`);
        }
    }
    

    async notifyLogin(phoneNumber: string, username: string) {
        const message = `🔐 Hola ${username}, se ha detectado un nuevo inicio de sesión en tu cuenta. Si no fuiste tú, cambia tu contraseña inmediatamente.`;
        await this.sendMessage(phoneNumber, message);
    }

    async notifyRegistration(phoneNumber: string, username: string, token: string) {
        const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
        
        const message = `👋 Hola ${username}, gracias por registrarte. Verifica tu cuenta aquí: \n\n ${verificationLink} \n(expira en 15 minutos).`;
        await this.sendMessage(phoneNumber, message);
    }
    
    
}