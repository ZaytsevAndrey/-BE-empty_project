import {
    Body,
    Controller,
    HttpCode,
    HttpException,
    HttpStatus,
    Post,
    Logger,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ApiError } from '../common/types/errors';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';

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

    constructor(private readonly authService: AuthService) {}

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
    @ApiResponse({ status: 200, description: 'Successful login', schema: { example: { access_token: 'string', refresh_token: 'string' } } })
    @ApiBody({ schema: { example: { username: 'user@example.com', password: 'password123' } } })
    @Post('login')
    @HttpCode(HttpStatus.OK)
    async login(@Body() loginDto: LoginDto) {
        this.logger.log(`Login request received: ${JSON.stringify(loginDto)}`);
        const tokens = await this.authService.validateUser(loginDto);
        this.logger.log('Login successful');
        return tokens;
    }

    @ApiOperation({ summary: 'Refresh token' })
    @ApiResponse({ status: 200, description: 'Tokens refreshed', schema: { example: { access_token: 'string', refresh_token: 'string' } } })
    @ApiBody({ schema: { example: { refresh_token: 'string' } } })
    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    async refreshToken(@Body('refresh_token') refreshToken: string) {
        this.logger.log(`Refresh token request received: ${refreshToken}`);
        const tokens = await this.authService.generateNewTokens(refreshToken);
        this.logger.log('Token refresh successful');
        return tokens;
    }

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

    @Post('forgot-password')
    @HttpCode(HttpStatus.OK)
    async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
        await this.authService.sendPasswordResetInstructions(forgotPasswordDto);
        return { message: 'Password reset instructions sent' };
    }
}
