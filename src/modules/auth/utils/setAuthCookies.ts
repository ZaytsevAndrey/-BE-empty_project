import { FastifyReply } from 'fastify';

export function setAuthCookies(reply: FastifyReply, tokens: { access_token: string; refresh_token: string }): void {
    reply.setCookie('access_token', tokens.access_token, { httpOnly: true });
    reply.setCookie('refresh_token', tokens.refresh_token, { httpOnly: true });
} 