import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { RefreshTokenEntity } from "../entities/refresh_token.entity";
import { ForbiddenException, Injectable, UnauthorizedException } from "@nestjs/common";
import { TokenService } from "./token/token.service";
import { UserValidationService } from "./shared/user-validation.service";
import * as bcrypt from 'bcrypt';
import { JwtPayload } from "../interfaces/jwt-payload.interface";
import { randomUUID } from "crypto";

@Injectable()
export class AuthTokenService {
    constructor(
        @InjectRepository(RefreshTokenEntity)
        private readonly refreshTokenRepository: Repository<RefreshTokenEntity>,

        private readonly tokenService: TokenService,
        private readonly userValidationService: UserValidationService
    ) { }

    //metodo para crear un nuevo token de acceso y refresco
    async refreshToken(refreshToken: string): Promise<{ accessToken: string, refreshToken: string }> {
        
        //usamos el metodo nuevo donde solo pasamos el refresh token y la secret
        const payload = await this.tokenService.verifyToken(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const userId = payload.sub;

        //validamos el usuario con el id que viene en el payload
        const user = await this.userValidationService.validateUserForRefresh(userId);

        //buscamos el token en la base de datos
        const storedToken = await this.refreshTokenRepository.findOne({
            where: { jti: payload.jti, userId: { idUser: user.idUser } },
            order: { createdAt: 'DESC' } // Asegurarse de obtener el último token
        });
        //verificamos si el token existe y si es valido
        if (!storedToken) throw new UnauthorizedException('Invalid refresh token');

        //validamos si el token coincide con el que tenemos en la base de datos
        if (storedToken.jti !== payload.jti) {
            throw new ForbiddenException('Invalid or reused refresh token');
        }
        //verificamos si el token es valido y si no ha sido revocado o expirado con el hash de la bd
        const isTokenValid = await bcrypt.compare(refreshToken, storedToken.token);
        if (!isTokenValid || storedToken.revoked || storedToken.expiresAt < new Date()) {
            throw new ForbiddenException('Access Denied');
        }
        //si todo es correcto, revocamos el token actulmente en la base de datos
        //y generamos un nuevo token de acceso y refresco
        storedToken.revoked = true;
        await this.refreshTokenRepository.save(storedToken);

        //este es el poyload estandar que se va a usar para crear el nuevo token en todos los casos donde se requiera
        const newPayload: JwtPayload = {
            sub: user.idUser,
            email: user.email,
            rol: [user.role.rolName],
            jti: randomUUID(),
        };

        // Generar nuevos tokens
        const newAccessToken = await this.tokenService.generateToken(newPayload, '1h', process.env.JWT_SECRET);
        const newRefreshToken = await this.tokenService.generateToken(newPayload, '7d', process.env.JWT_REFRESH_TOKEN);

        // Hashear el nuevo refresh token y guardarlo en la base de datos
        const hashedNewRefreshToken = await bcrypt.hash(newRefreshToken, 10);

        // Guardar el nuevo refresh token en la base de datos
        await this.refreshTokenRepository.save({
            userId: { idUser: user.idUser },
            token: hashedNewRefreshToken,
            jti: newPayload.jti, // Guardar el nuevo jti
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 días
            revoked: false, // El nuevo token no está revocado
        });

        return {
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        };
    }

    //metedo logout
    async logout(userId: number, refreshToken: string): Promise<void> {
        //verificamos el token
        const payload = await this.tokenService.verifyToken(refreshToken, process.env.REFRESH_TOKEN_SECRET);

        //validamos el usuario con el id que viene en el payload
        if (payload.sub !== userId) throw new ForbiddenException('error token, no match');

        //buscamos el usuario en la base de datos
        const user = await this.userValidationService.checkUserExistsById(userId);

        //buscamos el token en la base de datos
        const storedToken = await this.refreshTokenRepository.findOne({
            where: { jti: payload.jti, userId: { idUser: user.idUser } },
            order: { createdAt: 'DESC' }
        });

        //verificamos si el token existe
        if (!storedToken) throw new UnauthorizedException('Invalid refresh token');

        //validamos si el token coincide con el que tenemos en la base de datos
        if (storedToken.jti !== payload.jti) {
            throw new ForbiddenException('Invalid or reused refresh token');
        }
        //verificamos si el token es valido y si no ha sido revocado o expirado con el hash de la bd
        const isTokenValid = await bcrypt.compare(refreshToken, storedToken.token);
        if (!isTokenValid || storedToken.revoked || storedToken.expiresAt < new Date()) {
            throw new ForbiddenException('Access Denied');
        }

        storedToken.revoked = true; // Marcamos el token como revocado
        await this.refreshTokenRepository.save(storedToken);
        return;
    }
}