import { IsString, Matches, MinLength } from "class-validator";

export class UpdatePasswordDto {
    
    @IsString()
    @MinLength(8)
    @Matches(/^(?=.*[A-Z])(?=.*\d)(?=.*[a-z]).{8,}$/, {
        message: 'New password must be at least 8 characters long, contain an uppercase letter and a number',
    })
    newPassword: string;

    @IsString()
    @MinLength(8)
    confirmPassword: string;
}