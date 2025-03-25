import { Controller, Post, Body, BadRequestException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly usersService: UsersService,
    ) {}

    @Post('register')
    async register(@Body() body: { username: string; password: string }) {
        const existingUser = await this.usersService.findOne(body.username);
        if (existingUser) {
            throw new BadRequestException('Username already exists');
        }
        const user = await this.usersService.create(body.username, body.password);
        return { message: 'User registered successfully', userId: user.id };
    }

    @Post('login')
    async login(@Body() body: { username: string; password: string }) {
        return this.authService.validateUser(body.username, body.password)
            .then(user => this.authService.login(user));
    }
}
