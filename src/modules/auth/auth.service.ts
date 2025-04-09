import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, UpdateResult } from 'typeorm';
import { randomBytes } from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { Req } from '@nestjs/common';

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
        private readonly jwtService: JwtService,
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

        user.resetToken = null;
        await this.usersRepo.save(user);

        this.emailService.sendEmail(user.email, 'Password Reset', 'Your password has been reset successfully.');
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
        user.resetToken = resetToken;
        await this.usersRepo.save(user);

        this.sendPasswordResetEmail(user.email, resetToken);
    }

    private createTokenPair(userId: number): { access_token: string; refresh_token: string } {
        const payload = { sub: userId };
        const access_token = this.jwtService.sign(payload, { expiresIn: '15m' });
        const refresh_token = this.jwtService.sign(payload, { expiresIn: '7d' });
        return { access_token, refresh_token };
    }

    private async setRefreshToken(userId: number, token: string): Promise<void> {
        await this.usersRepo.update({ id: userId }, { refreshToken: token });
    }

    private async getUserIfRefreshTokenMatches(token: string): Promise<User | null> {
        const user = await this.usersRepo.findOne({ where: { refreshToken: token } });
        return user;
    }

    private async getUserByResetToken(token: string): Promise<User | null> {
        return this.usersRepo.findOne({ where: { resetToken: token } });
    }

    private generateVerificationCode(): string {
        // Логіка для генерації коду верифікації
        return '123456';
    }

    private async sendVerificationEmail(email: string, code: string): Promise<void> {
        // Логіка для відправки електронного листа з кодом верифікації
    }

    private generateResetToken(): string {
        return randomBytes(32).toString('hex');
    }

    private async sendPasswordResetEmail(email: string, token: string): Promise<void> {
        const resetLink = `${process.env.APP_URL}/reset-password?token=${token}`;
        const subject = 'Password Reset Instructions';
        const text = `To reset your password, please click the following link: ${resetLink}`;

        await this.emailService.sendEmail(email, subject, text);
    }

    async updatePassword(userId: number, newPassword: string): Promise<UpdateResult> {
        return this.usersRepo.update({ id: userId }, { password: newPassword });
    }

    async logout(userId: number): Promise<void> {
        console.log(`Logging out user with ID: ${userId}`);
        await this.usersRepo.update({ id: userId }, { refreshToken: null });
        console.log(`User with ID: ${userId} logged out successfully`);
    }
}
