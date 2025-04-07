import { IsEmail } from "class-validator";

export class ResendMailDto {
    @IsEmail({}, {message: 'Invalid email'})
    email: string;
}