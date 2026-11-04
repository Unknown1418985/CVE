import { Body, Controller, Delete, Get, HttpCode, Param, Post, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { z } from 'zod';

import { CurrentPrincipal, type AuthenticatedPrincipal } from '@cve/auth';
import { sessionIdParamSchema, type UserSession } from '@cve/contracts';
import { parseRequest } from '@cve/shared';

import { actorContext } from '../common/request-context.js';
import { SessionsService } from './sessions.service.js';

const logoutRequestSchema = z
  .strictObject({ allSessions: z.boolean().default(false) })
  .default({ allSessions: false });

@ApiTags('sessions')
@ApiBearerAuth()
@Controller()
export class SessionsController {
  constructor(private readonly sessions: SessionsService) {}

  @Get('me/sessions')
  @ApiOperation({ summary: 'Active Keycloak sessions of the caller' })
  async list(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
  ): Promise<{ data: UserSession[] }> {
    return { data: await this.sessions.list(principal.subject, principal.sessionId) };
  }

  @Delete('me/sessions/:sessionId')
  @HttpCode(204)
  @ApiOperation({ summary: 'Revoke one of the caller sessions (e.g. a lost device)' })
  async revoke(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Req() req: Request,
    @Param('sessionId') sessionId: string,
  ): Promise<void> {
    const id = parseRequest(sessionIdParamSchema, sessionId);
    await this.sessions.revoke(actorContext(req, principal), principal.subject, id, 'user-revoked');
  }

  @Post('auth/logout')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Secure logout',
    description:
      'Ends the Keycloak session behind the access token (or every session with `allSessions: true`), which invalidates its refresh tokens. The gateway rejects the access token as soon as the session is gone. Clients must also discard their tokens.',
  })
  async logout(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Req() req: Request,
    @Body() body: unknown,
  ): Promise<{ data: { revokedSessions: number } }> {
    const { allSessions } = parseRequest(logoutRequestSchema, body ?? undefined);
    const revoked = await this.sessions.logout(actorContext(req, principal), allSessions);
    return { data: { revokedSessions: revoked } };
  }
}
