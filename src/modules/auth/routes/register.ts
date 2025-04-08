import { z } from 'zod';
import { FastifyInstance } from 'fastify';
import prisma from '../../../shared/db/client';
import { hashPassword } from '../utils/hashPassword';
import { createTokenPair } from '../utils/createTokenPair';
import { ApiError } from '../../common/types/errors';
import { setAuthCookies } from '../utils/setAuthCookies';

const registerSchema = z.object({
    username: z.string().email(),
    password: z.string().min(6),
    confirmPassword: z.string().min(6),
});

export async function registerRoute(app: FastifyInstance) {
    app.post('/auth/register', async (request, reply) => {
        const body = registerSchema.safeParse(request.body);

        if (!body.success) {
            const fieldErrors: Record<string, string> = {};
            for (const issue of body.error.issues) {
                const field = issue.path[0];
                if (typeof field === 'string') {
                    fieldErrors[field] = issue.message;
                }
            }

            throw new ApiError('VALIDATION_ERROR', fieldErrors);
        }

        const { username, password, confirmPassword } = body.data;

        if (password !== confirmPassword) {
            throw new ApiError('PASSWORDS_DO_NOT_MATCH', { confirmPassword: 'Паролі не співпадають' });
        }

        const existingUser = await prisma.user.findUnique({
            where: { username },
        });

        if (existingUser) {
            throw new ApiError('USER_ALREADY_EXISTS', { username: 'Користувач з таким email вже існує' });
        }

        const hashedPassword = await hashPassword(password);

        const user = await prisma.user.create({
            data: {
                username,
                password: hashedPassword,
            },
        });

        const tokens = await createTokenPair(user.id);
        setAuthCookies(reply, tokens);

        return reply.send({ userId: user.id });
    });
}
