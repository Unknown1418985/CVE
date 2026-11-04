import { Body, Controller, Get, Patch, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';

import { CurrentPrincipal, type AuthenticatedPrincipal } from '@cve/auth';
import {
  updateProfileRequestSchema,
  type CredentialActionLink,
  type UserProfile,
} from '@cve/contracts';
import { parseRequest } from '@cve/shared';

import { actorContext } from '../common/request-context.js';
import { ProfileService } from './profile.service.js';

@ApiTags('profile')
@ApiBearerAuth()
@Controller('me')
export class ProfileController {
  constructor(private readonly profiles: ProfileService) {}

  @Get()
  @ApiOperation({ summary: 'Profile, roles and effective permissions of the caller' })
  async me(@CurrentPrincipal() principal: AuthenticatedPrincipal): Promise<{ data: UserProfile }> {
    return { data: await this.profiles.me(principal) };
  }

  @Patch()
  @ApiOperation({
    summary: 'Update the caller profile',
    description:
      'Names are written to Keycloak; display name, job title and time zone are stored by the Identity Service. Email and username are managed in Keycloak only.',
  })
  async update(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Req() req: Request,
    @Body() body: unknown,
  ): Promise<{ data: UserProfile }> {
    const request = parseRequest(updateProfileRequestSchema, body);
    return { data: await this.profiles.update(actorContext(req, principal), request) };
  }

  @Get('credentials/actions')
  @ApiOperation({
    summary: 'Links to change the password or configure TOTP on Keycloak',
    description:
      'The web client adds state, nonce and PKCE parameters and redirects the browser. Credentials are never sent to the platform API.',
  })
  credentialActions(): { data: CredentialActionLink[] } {
    return { data: this.profiles.credentialActions() };
  }
}
