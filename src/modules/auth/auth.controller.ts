import {
    Body,
    Controller,
    HttpCode,
    HttpException,
    HttpStatus,
    Post,
    Logger,
    Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ApiError } from '../common/types/errors';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { JwtService } from '@nestjs/jwt';

const ERROR_CODES = {
    WRONG_PASSWORD_ERROR: 800,
    USER_NOT_FOUND_ERROR: 801,
    INVALID_TOKEN_ERROR: 802,
    USER_ALREADY_EXISTS_ERROR: 803,
    INVALID_EMAIL_FORMAT_ERROR: 804,
    INVALID_JWT: 805,
    EMPTY_JWT: 806,
    INVALID_SESSION: 807,
    INVALID_REFRESH_TOKEN: 808,
};

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    private readonly logger = new Logger(AuthController.name);

    constructor(
        private readonly authService: AuthService,
        private readonly jwtService: JwtService,
    ) {}

    private extractUserIdFromRequest(req): number {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            throw new Error('Authorization header missing');
        }
        const token = authHeader.split(' ')[1];
        const payload = this.jwtService.verify(token);
        return payload.sub;
    }

    @ApiOperation({ summary: 'Register a new user' })
    @ApiBody({ schema: { example: { email: 'user@example.com', password: 'password123', confirmPassword: 'password123' } } })
    @ApiResponse({ status: 201, description: 'User registered successfully' })
    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    async register(@Body() registerDto: RegisterDto) {
        this.logger.log(`Register request received: ${JSON.stringify(registerDto)}`);
        try {
            await this.authService.registerUser(registerDto);
            this.logger.log('Registration successful');
            return { message: 'Registration successful' };
        } catch (error) {
            this.logger.error(`Registration failed: ${error.message}`);
            if (error instanceof ApiError) {
                throw new HttpException(
                    {
                        code: ERROR_CODES[error.code] || HttpStatus.BAD_REQUEST,
                        fields: error.fields,
                    },
                    HttpStatus.BAD_REQUEST
                );
            }

            throw new HttpException('Internal server error', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @ApiOperation({ summary: 'User login' })
    @ApiBody({ schema: { example: { username: 'user@example.com', password: 'password123' } } })
    @ApiResponse({ status: 200, description: 'Successful login', schema: { example: { access_token: 'string', refresh_token: 'string' } } })
    @Post('login')
    @HttpCode(HttpStatus.OK)
    async login(@Body() loginDto: LoginDto) {
        this.logger.log(`Login request received: ${JSON.stringify(loginDto)}`);
        const tokens = await this.authService.validateUser(loginDto);
        this.logger.log('Login successful');
        return tokens;
    }

    @ApiOperation({ summary: 'Refresh tokens' })
    @ApiBody({ schema: { example: { refreshToken: 'string' } } })
    @ApiResponse({ status: 200, description: 'Tokens refreshed', schema: { example: { access_token: 'string', refresh_token: 'string' } } })
    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    async refreshToken(@Body('refresh_token') refreshToken: string) {
        this.logger.log(`Refresh token request received: ${refreshToken}`);
        const tokens = await this.authService.generateNewTokens(refreshToken);
        this.logger.log('Token refresh successful');
        return tokens;
    }

    @ApiOperation({ summary: 'Reset password' })
    @ApiBody({ schema: { example: { token: 'reset_token', newPassword: 'newPassword123' } } })
    @ApiResponse({ status: 200, description: 'Password reset successful' })
    @Post('reset-password')
    @HttpCode(HttpStatus.OK)
    async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
        await this.authService.resetUserPassword(resetPasswordDto);
        return { message: 'Password reset successful' };
    }

    @Post('send-verification-code')
    @HttpCode(HttpStatus.OK)
    async sendVerificationCode(@Body('email') email: string) {
        await this.authService.generateAndSendCode(email);
        return { message: 'Verification code sent' };
    }

    @ApiOperation({ summary: 'Forgot password' })
    @ApiBody({ schema: { example: { email: 'user@example.com' } } })
    @ApiResponse({ status: 200, description: 'Password reset instructions sent' })
    @Post('forgot-password')
    @HttpCode(HttpStatus.OK)
    async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
        this.logger.log(`Forgot password request received: ${JSON.stringify(forgotPasswordDto)}`);
        await this.authService.sendPasswordResetInstructions(forgotPasswordDto);
        this.logger.log('Password reset instructions sent');
        return { message: 'Password reset instructions sent' };
    }

    @ApiOperation({ summary: 'Logout user' })
    @ApiResponse({ status: 200, description: 'User logged out successfully' })
    @Post('logout')
    @HttpCode(HttpStatus.OK)
    async logout(@Req() req) {
        const userId = this.extractUserIdFromRequest(req);
        await this.authService.logout(userId);
        return { message: 'User logged out successfully' };
    }
}
