import { Module } from '@nestjs/common';
import { WhatsappService } from './services/whatsapp.service';

@Module({
    controllers: [],
    providers: [WhatsappService],
    exports: [WhatsappService],
  })
  export class WhatsappModule {}
  