import {
    Controller,
    Post,
    Get,
    Body,
    Req,
    UseGuards,
    ValidationPipe,
    BadRequestException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { UnauthorizedException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';

import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';



@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly usersService: UsersService,
    ) {}

    @Post('register')
    async register(@Body(new ValidationPipe({ whitelist: true })) registerDto: RegisterDto) {
        const existingUser = await this.usersService.findOne(registerDto.username);
        if (existingUser) {
            throw new BadRequestException('Username already exists');
        }
        const user = await this.usersService.create(registerDto.username, registerDto.password);
        return { message: 'User registered successfully', userId: user.id };
    }

    @Post('login')
    async login(@Body(new ValidationPipe({ whitelist: true })) loginDto: LoginDto) {
        const user = await this.authService.validateUser(loginDto.username, loginDto.password);
        return this.authService.login(user);
    }

    @Get('me')
    @UseGuards(AuthGuard('jwt'))
    getProfile(@Req() req: Request & { user: any }) {
        return req.user;
    }

    @Post('forgot-password')
    async forgotPassword(@Body(new ValidationPipe()) body: ForgotPasswordDto) {
        const user = await this.usersService.findOne(body.username);
        if (!user) throw new BadRequestException('User not found');

        const resetToken = jwt.sign(
            { userId: user.id },
            process.env.JWT_SECRET!,
            { expiresIn: '15m' }
        );

        console.log(`🔐 Password reset token for ${body.username}:`);
        console.log(`http://localhost:3000/auth/reset-password?token=${resetToken}`);

        return { message: 'Password reset link has been sent (console only).' };
    }

    @Post('reset-password')
    async resetPassword(@Body(new ValidationPipe()) body: ResetPasswordDto) {
        try {
            const payload: any = jwt.verify(body.token, process.env.JWT_SECRET!);
            const user = await this.usersService.findById(payload.userId);
            if (!user) throw new BadRequestException('Invalid token');

            await this.usersService.updatePassword(user.id, body.newPassword);
            return { message: 'Password updated successfully' };
        } catch (err) {
            throw new BadRequestException('Invalid or expired token');
        }
    }

    @Post('refresh')
    async refresh(@Body() body: { refresh_token: string }) {
        try {
            const payload: any = jwt.verify(body.refresh_token, process.env.JWT_SECRET!);
            const user = await this.usersService.getUserIfRefreshTokenMatches(payload.sub, body.refresh_token);

            if (!user) throw new UnauthorizedException('Invalid refresh token');

            const newAccessToken = jwt.sign(
                { username: user.username, sub: user.id },
                process.env.JWT_SECRET!,
                { expiresIn: '15m' }
            );

            return { access_token: newAccessToken };
        } catch (e) {
            throw new UnauthorizedException('Invalid or expired refresh token');
        }
    }

    @Post('logout')
    @UseGuards(AuthGuard('jwt'))
    async logout(@Req() req: Request & { user: any }) {
        await this.usersService.removeRefreshToken(req.user.userId);
        return { message: 'Logged out successfully' };
    }
}
