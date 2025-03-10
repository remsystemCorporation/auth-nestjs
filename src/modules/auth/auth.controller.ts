import { Body, ClassSerializerInterceptor, Controller, Get, HttpCode, HttpStatus, Patch, Post, Query, UseInterceptors } from '@nestjs/common';
import { LoginUserDto } from './dto/login.dto';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResendMailDto } from './dto/resend-email-verify.dto';
import { UpdatePasswordDto } from './dto/reset-password.dto';


@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post('login')
    @HttpCode(HttpStatus.OK)
    async loginUser(
        @Body() loginUserDto: LoginUserDto,
    ): Promise<{ accessToken: string }> {
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

    @Patch('update-password')
    async updatePassword(
        @Query('token') token: string,
        @Body() updatePasswordDto: UpdatePasswordDto
    ): Promise<string> {
        return this.authService.updatePasswords(token, updatePasswordDto);
    }
}
