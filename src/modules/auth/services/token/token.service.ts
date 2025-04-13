import { ForbiddenException, Injectable, UnauthorizedException } from "@nestjs/common";
import { JsonWebTokenError, JwtService, NotBeforeError, TokenExpiredError } from "@nestjs/jwt";
import { JwtPayload } from "../../interfaces/jwt-payload.interface";

@Injectable()
export class TokenService {
    constructor(private readonly jwtService: JwtService) { }

    // generador de tokens con todo lo necesario para la firma y la expiracion
    async generateToken(payload: JwtPayload, expiresIn: string, secretKey: string): Promise<string> {
        return this.jwtService.sign(payload, {
            expiresIn,
            secret: secretKey,
        });
    }

    // verificador de tokens con todo lo necesario para la firma y la expiracion
    async verifyToken(token: string, secretKey: string): Promise <JwtPayload>{
        try {
            const payload = this.jwtService.verify(token, {
                secret: secretKey,
            });
            return payload as JwtPayload;
        } catch (error) {
            if (error instanceof TokenExpiredError) {
                throw new UnauthorizedException('token expired');
            } else if (error instanceof JsonWebTokenError) {
                throw new UnauthorizedException('Invalid token');
            } else if (error instanceof NotBeforeError) {
                throw new ForbiddenException('Token not active yet');
            } else {
                console.error('Unknown error verifying token:', error);
                throw new UnauthorizedException('Could not validate token');
            }
        }
    }
}