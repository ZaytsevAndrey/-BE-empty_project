import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import prisma from '../../../shared/db/client';
import { z } from 'zod';
import { generateVerificationCode } from '../utils/codeGenerator';

const registerSchema = z.object({
    username: z.string().min(3).max(32),
    email: z.string().email(),
    password: z.string().min(8),
});

export const register = async (req: Request, res: Response) => {
    const parseResult = registerSchema.safeParse(req.body);

    if (!parseResult.success) {
        return res.status(400).json({
            code: 'VALIDATION_ERROR',
            fields: parseResult.error.flatten().fieldErrors,
        });
    }

    const { username, email, password } = parseResult.data;

    const existingUser = await prisma.user.findFirst({
        where: {
            OR: [
                { email: email.toLowerCase() },
                { username: username },
            ],
        },
    });

    if (existingUser) {
        return res.status(400).json({
            code: 'USER_ALREADY_EXISTS',
            fields: {
                email: ['Користувач з такою поштою або логіном вже існує'],
            },
        });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = generateVerificationCode();

    await prisma.user.create({
        data: {
            username,
            email: email.toLowerCase(),
            password: hashedPassword,
            emailVerificationCode: verificationCode,
        },
    });

    return res.status(201).json({ message: 'Користувача створено' });
};
