import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Matches,
  Length,
  IsOptional,
  IsDateString,
  IsMobilePhone
} from 'class-validator';

export class RegisterUserDto {
  @IsNotEmpty({ message: 'Full name is required.' })
  @IsString({ message: 'Full name must be a valid string.' })
  @Length(2, 255, { message: 'Full name must be between 2 and 255 characters long.' })
  fullName: string;

  @IsNotEmpty({ message: 'Email is required.' })
  @IsEmail({}, { message: 'Email is not valid.' })
  email: string;

  @IsNotEmpty({ message: 'Password is required.' })
  @IsString({ message: 'Password must be a valid string.' })
  @Length(8, 255, { message: 'Password must be at least 8 characters long.' })
  @Matches(/(?=.*[A-Z])(?=.*[0-9])(?=.*[.]).{8,}/, {
    message:
      'Password must contain at least one uppercase letter, one number, one special character like a dot, and be at least 8 characters long.',
  })
  password: string;

  // 🟨 Información adicional del usuario (opcional o requerida, tú decides)

  @IsOptional()
  @IsString({ message: 'Company must be a string.' })
  company: string;

  @IsOptional()
  @IsMobilePhone()
  phone: string;

  @IsOptional()
  @IsString({ message: 'Address must be a string.' })
  address: string;

  @IsOptional()
  @IsDateString({}, { message: 'Birthdate must be a valid date (YYYY-MM-DD).' })
  birthdate: string;
}
