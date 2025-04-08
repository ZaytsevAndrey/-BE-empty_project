import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class RegisterDto {
    // @IsNotEmpty({ message: 'USERNAME_REQUIRED' })
    username: string;

    @IsEmail({}, { message: 'INVALID_EMAIL' })
    email: string;

    @IsNotEmpty({ message: 'WEAK_PASSWORD' })
    @MinLength(8, { message: 'WEAK_PASSWORD' })
    password: string;

    @IsNotEmpty({ message: 'PASSWORDS_DO_NOT_MATCH' })
    confirmPassword: string;
}
