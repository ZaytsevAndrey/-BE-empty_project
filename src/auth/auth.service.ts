import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';
import * as jwt from 'jsonwebtoken';
import { User } from '../users/user.entity';


@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
    ) {}

    async validateUser(username: string, password: string): Promise<any> {
        const user = await this.usersService.findOne(username);
        if (user && (await bcrypt.compare(password, user.password))) {
            const { password, ...result } = user;
            return result;
        }
        throw new UnauthorizedException('Invalid credentials');
    }

    async login(user: User) {
        const payload = { username: user.username, sub: user.id };

        const access_token = jwt.sign(payload, process.env.JWT_SECRET!, { expiresIn: '15m' });
        const refresh_token = jwt.sign(payload, process.env.JWT_SECRET!, { expiresIn: '7d' });

        await this.usersService.setRefreshToken(user.id, refresh_token);

        return { access_token, refresh_token };
    }
}
