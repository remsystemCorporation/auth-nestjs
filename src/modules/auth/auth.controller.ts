import { Body, Controller, Get, HttpCode, HttpStatus, Patch, Post, Query, Req } from '@nestjs/common';
import { LoginUserDto } from './dto/login.dto';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResendMailDto } from './dto/resend-email-verify.dto';
import { UpdatePasswordDto } from './dto/reset-password.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { Auth } from './decorators/auth.decorator';
import { ValidRoles } from './interfaces/valid-roles.interface';
import { Request } from 'express';
import { LogoutDto } from './dto/logout.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('login')
    @HttpCode(HttpStatus.OK)
    async loginUser(
        @Body() loginUserDto: LoginUserDto,
    ): Promise<{ accessToken: string, refreshToken: string }> {
        return this.authService.login(loginUserDto);
    }

    @Post('register')
    @HttpCode(201)
    async registerAuth(@Body() registerUserDto: RegisterUserDto) {
        return this.authService.register(registerUserDto);
    }

    @Get('verify-email')
    async verifyEmail(@Query('token') token: string): Promise<string> {
        return this.authService.verifyEmail(token);
    }

    @Post('resend-verification-email')
    async resendVerificationEmail(@Body() resendMailDto: ResendMailDto): Promise<string> {
        return this.authService.resendVerificationEmail(resendMailDto);
    }

    @Post('forgot-password')
    async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto): Promise<string> {
        return this.authService.forgotPassword(forgotPasswordDto)
    }

    @Post('reset-password')
    async resetPassword(
        @Query('token') token: string,
        @Body() updatePasswordDto: UpdatePasswordDto
    ): Promise<string> {
        return this.authService.resetPassword(token, updatePasswordDto);
    }

    @Post('refresh-token')
    @HttpCode(HttpStatus.OK)
    async refreshToken(
        @Body() refreshTokenDto: RefreshTokenDto,
    ): Promise<{ accessToken: string, refreshToken: string }> {
        return this.authService.refreshToken(refreshTokenDto.refreshToken);
    }

    @Post('logout')
    @HttpCode(HttpStatus.OK)
    @Auth(ValidRoles.client, ValidRoles.Admin, ValidRoles.Super)
    async logout( @Req() req: Request, @Body() logoutDto: LogoutDto): Promise<void> {
        
        const userId = req.user['idUser'];
        await this.authService.logout(userId, logoutDto.refreshToken);
        return;
    }
}
