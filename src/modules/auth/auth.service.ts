import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, UpdateResult } from 'typeorm';

import { User } from '../users/user.entity';
import { RegisterDto } from './dto/register.dto';
import { ApiError } from '../common/types/errors';
import { LoginDto } from './dto/login.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { EmailService } from '../common/services/email.service';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private readonly usersRepo: Repository<User>,
        private readonly emailService: EmailService,
    ) {}

    async registerUser(dto: RegisterDto): Promise<void> {
        const { email, password, confirmPassword } = dto;

        if (password !== confirmPassword) {
            throw new ApiError('PASSWORDS_DO_NOT_MATCH', {
                confirmPassword: 'Паролі не співпадають',
            });
        }

        const existing = await this.usersRepo.findOneBy({ email });
        if (existing) {
            throw new ApiError('EMAIL_ALREADY_EXISTS', {
                email: 'Цей email вже використовується',
            });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const user = this.usersRepo.create({
            email,
            password: passwordHash,
            isEmailVerified: false,
        });

        await this.usersRepo.save(user);

        // Send welcome email
        await this.emailService.sendEmail(email, 'Welcome!', 'Thank you for registering!');
    }

    async validateUser(dto: LoginDto): Promise<{ access_token: string; refresh_token: string }> {
        const { username, password } = dto;
        const user = await this.usersRepo.findOneBy({ username });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            throw new ApiError('INVALID_CREDENTIALS', { username: 'Неправильний логін або пароль' });
        }

        const tokens = this.createTokenPair(user.id);
        await this.setRefreshToken(user.id, tokens.refresh_token);
        return tokens;
    }

    async generateNewTokens(refreshToken: string): Promise<{ access_token: string; refresh_token: string }> {
        const user = await this.getUserIfRefreshTokenMatches(refreshToken);

        if (!user) {
            throw new ApiError('INVALID_REFRESH_TOKEN', { refreshToken: 'Недійсний токен оновлення' });
        }

        const tokens = this.createTokenPair(user.id);
        await this.setRefreshToken(user.id, tokens.refresh_token);
        return tokens;
    }

    async resetUserPassword(dto: ResetPasswordDto): Promise<void> {
        const { token, newPassword } = dto;
        const user = await this.getUserByResetToken(token);

        if (!user) {
            throw new ApiError('INVALID_RESET_TOKEN', { token: 'Недійсний токен скидання' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await this.updatePassword(user.id, hashedPassword);

        // Send password reset confirmation email
        await this.emailService.sendEmail(user.email, 'Password Reset', 'Your password has been reset successfully.');
    }

    async generateAndSendCode(email: string): Promise<void> {
        const user = await this.usersRepo.findOneBy({ email });

        if (!user) {
            throw new ApiError('EMAIL_NOT_FOUND', { email: 'Електронна пошта не знайдена' });
        }

        const code = this.generateVerificationCode();
        await this.sendVerificationEmail(user.email, code);
    }

    async sendPasswordResetInstructions(dto: ForgotPasswordDto): Promise<void> {
        const { email } = dto;
        const user = await this.usersRepo.findOneBy({ email });

        if (!user) {
            throw new ApiError('EMAIL_NOT_FOUND', { email: 'Електронна пошта не знайдена' });
        }

        const resetToken = this.generateResetToken();
        await this.sendPasswordResetEmail(user.email, resetToken);
    }

    private createTokenPair(userId: number): { access_token: string; refresh_token: string } {
        // Логіка для створення токенів
        return { access_token: 'access_token', refresh_token: 'refresh_token' };
    }

    private async setRefreshToken(userId: number, token: string): Promise<void> {
        await this.usersRepo.update({ id: userId }, { refreshToken: token });
    }

    private async getUserIfRefreshTokenMatches(token: string): Promise<User | null> {
        const user = await this.usersRepo.findOne({ where: { refreshToken: token } });
        return user;
    }

    private async getUserByResetToken(token: string): Promise<User | null> {
        // Логіка для отримання користувача за токеном скидання
        return null;
    }

    private generateVerificationCode(): string {
        // Логіка для генерації коду верифікації
        return '123456';
    }

    private async sendVerificationEmail(email: string, code: string): Promise<void> {
        // Логіка для відправки електронного листа з кодом верифікації
    }

    private generateResetToken(): string {
        // Логіка для генерації токену скидання
        return 'reset_token';
    }

    private async sendPasswordResetEmail(email: string, token: string): Promise<void> {
        // Логіка для відправки електронного листа з інструкціями для скидання паролю
    }

    async updatePassword(userId: number, newPassword: string): Promise<UpdateResult> {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        return this.usersRepo.update({ id: userId }, { password: hashedPassword });
    }
}
