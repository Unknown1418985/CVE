import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Patch,
  Post,
  Put,
  Query,
  Req,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { z } from 'zod';

import { CurrentPrincipal, RequirePermissions, type AuthenticatedPrincipal } from '@cve/auth';
import {
  listUsersQuerySchema,
  sessionIdParamSchema,
  updateUserRolesRequestSchema,
  updateUserStatusRequestSchema,
  type PaginationMeta,
  type UserSession,
  type UserSummary,
} from '@cve/contracts';
import { parseRequest } from '@cve/shared';

import { actorContext } from '../common/request-context.js';
import { SessionsService } from '../sessions/sessions.service.js';
import { UsersService } from './users.service.js';

const userIdSchema = z.uuid({ message: 'invalid user ID' });

@ApiTags('users')
@ApiBearerAuth()
@RequirePermissions('user:read')
@Controller('users')
export class UsersController {
  constructor(
    private readonly users: UsersService,
    private readonly sessions: SessionsService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'List and search users' })
  async list(@Query() query: unknown): Promise<{ data: UserSummary[]; meta: PaginationMeta }> {
    return this.users.list(parseRequest(listUsersQuerySchema, query));
  }

  @Get(':userId')
  @ApiOperation({ summary: 'Get one user with effective platform roles' })
  async get(@Param('userId') userId: string): Promise<{ data: UserSummary }> {
    return { data: await this.users.get(parseRequest(userIdSchema, userId)) };
  }

  @Put(':userId/roles')
  @RequirePermissions('role:assign')
  @ApiOperation({
    summary: 'Replace the directly assigned platform roles of a user',
    description:
      'Administrator and Super Admin can only be granted or revoked by a Super Admin. Removing roles ends the user sessions.',
  })
  async setRoles(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Req() req: Request,
    @Param('userId') userId: string,
    @Body() body: unknown,
  ): Promise<{ data: UserSummary }> {
    return {
      data: await this.users.setRoles(
        actorContext(req, principal),
        parseRequest(userIdSchema, userId),
        parseRequest(updateUserRolesRequestSchema, body),
      ),
    };
  }

  @Patch(':userId/status')
  @RequirePermissions('user:manage')
  @ApiOperation({ summary: 'Enable or disable a user; disabling ends all sessions' })
  async setStatus(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Req() req: Request,
    @Param('userId') userId: string,
    @Body() body: unknown,
  ): Promise<{ data: UserSummary }> {
    return {
      data: await this.users.setStatus(
        actorContext(req, principal),
        parseRequest(userIdSchema, userId),
        parseRequest(updateUserStatusRequestSchema, body),
      ),
    };
  }

  @Post(':userId/credentials/require-password-update')
  @HttpCode(200)
  @RequirePermissions('user:manage')
  @ApiOperation({
    summary: 'Require a password change at next login',
    description: 'Sets the Keycloak UPDATE_PASSWORD required action and ends all sessions.',
  })
  async requirePasswordUpdate(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Req() req: Request,
    @Param('userId') userId: string,
  ): Promise<{ data: UserSummary }> {
    return {
      data: await this.users.requirePasswordUpdate(
        actorContext(req, principal),
        parseRequest(userIdSchema, userId),
      ),
    };
  }

  @Get(':userId/sessions')
  @RequirePermissions('session:manage')
  @ApiOperation({ summary: 'Active sessions of a user' })
  async listSessions(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('userId') userId: string,
  ): Promise<{ data: UserSession[] }> {
    const id = parseRequest(userIdSchema, userId);
    await this.users.assertMayManageSessions(principal, id);
    return { data: await this.sessions.list(id) };
  }

  @Delete(':userId/sessions/:sessionId')
  @HttpCode(204)
  @RequirePermissions('session:manage')
  @ApiOperation({ summary: 'Revoke one session of a user' })
  async revokeSession(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Req() req: Request,
    @Param('userId') userId: string,
    @Param('sessionId') sessionId: string,
  ): Promise<void> {
    const id = parseRequest(userIdSchema, userId);
    await this.users.assertMayManageSessions(principal, id);
    await this.sessions.revoke(
      actorContext(req, principal),
      id,
      parseRequest(sessionIdParamSchema, sessionId),
      'admin-revoked',
    );
  }

  @Post(':userId/logout')
  @HttpCode(200)
  @RequirePermissions('session:manage')
  @ApiOperation({ summary: 'End every session of a user' })
  async logout(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Req() req: Request,
    @Param('userId') userId: string,
  ): Promise<{ data: { revokedSessions: number } }> {
    const id = parseRequest(userIdSchema, userId);
    await this.users.assertMayManageSessions(principal, id);
    const revoked = await this.sessions.revokeAll(
      actorContext(req, principal),
      id,
      'admin-revoked',
    );
    return { data: { revokedSessions: revoked } };
  }
}
