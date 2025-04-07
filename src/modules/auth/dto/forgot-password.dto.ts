import { IsEmail } from "class-validator";

export class ForgotPasswordDto {
    @IsEmail({}, {message: 'Invalid email'})
    email: string;
}