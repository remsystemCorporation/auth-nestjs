import { BadRequestException, ForbiddenException, Injectable, UnauthorizedException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { UserEntity } from "src/modules/users/entities/user.entity";
import { Repository } from "typeorm";

@Injectable()
export class UserValidationService {
    constructor(
        @InjectRepository(UserEntity)
        private readonly userRepository: Repository<UserEntity>,
    ) { }

    //buscamos por email y validamos
    async validateUser(email: string): Promise<UserEntity> {
        const user = await this.userRepository.findOne({
            where: { email },
            relations: { role: true }
        });
        //si no quieres que se revele si tienes un usuario registrado con ese correo o no. si no retonar el usuario no encontrado
        if (!user) throw new BadRequestException('Email or password is incorrect');
        if (!user.isActive) throw new ForbiddenException('Account suspended. Contact support.');
        if (user.deletedAt) throw new ForbiddenException('Account pending deletion.');
        if (!user.isVerified) throw new UnauthorizedException('Email verification required.');

        return user;
    }

    //buscamos por email
    async checkUserExistsEmail(email: string): Promise<UserEntity> {
        const user = await this.userRepository.findOne({
            where: { email },
            relations: { role: true }
        });
        return user;
    }

    //buscamos por id
    async checkUserExistsById(idUser: number): Promise<UserEntity> {
        const user = await this.userRepository.findOne({
            where: { idUser },
            relations: { role: true }
        });
        return user;
    }

    //buscamos por id y validamos para el refresh token
    async validateUserForRefresh(userId: number): Promise<UserEntity> {
        const user = await this.userRepository.findOne({
            where: { idUser: userId },
            relations: { role: true },
            select: ['idUser', 'email', 'isActive', 'isVerified', 'deletedAt', 'role']
        });

        if (!user || !user.isActive || user.deletedAt || !user.isVerified) {
            throw new ForbiddenException('Access Denied');
        }

        return user;
    }
}
