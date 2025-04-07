import { IsEmail, IsString, Matches, MinLength, MaxLength } from 'class-validator';

export class LoginUserDto {
  @IsEmail({}, { message: 'The email must be a valid email address.' })
  readonly email: string;

  @IsString({ message: 'The password must be a valid string.' })
  @MinLength(6, { message: 'The password must be at least 6 characters long.' })
  @MaxLength(255, { message: 'The password cannot be longer than 255 characters.' })
  @Matches(/(?=.*[A-Z])(?=.*[0-9])(?=.*[.]).{6,}/, {
    message: 'The password must contain at least one uppercase letter, one number, and one special character like a dot.',
  })
  readonly password: string;
}
