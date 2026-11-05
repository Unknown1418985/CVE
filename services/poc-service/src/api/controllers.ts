import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { ApiBearerAuth, ApiHeader, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request, Response } from 'express';
import { z } from 'zod';

import { CurrentPrincipal, RequirePermissions, type AuthenticatedPrincipal } from '@cve/auth';
import {
  buildPaginationMeta,
  changeVerificationRequestSchema,
  createAssociationRequestSchema,
  IDEMPOTENCY_KEY_HEADER,
  listDiscoveryRunsQuerySchema,
  listPocArtifactsQuerySchema,
  listPocAssociationsQuerySchema,
  listPocOwnersQuerySchema,
  listPocReferencesQuerySchema,
  listPocRepositoriesQuerySchema,
  paginationQuerySchema,
  reviewAssociationRequestSchema,
  triggerDiscoveryRequestSchema,
  type DiscoveryRun,
  type PaginationMeta,
  type PocArtifact,
  type PocArtifactDetail,
  type PocAssociation,
  type PocConnectorStatus,
  type PocOwner,
  type PocReference,
  type PocRepository,
  type RepositoryCommit,
  type TriggerDiscoveryResponse,
  type VerificationEvent,
} from '@cve/contracts';
import { parseRequest } from '@cve/shared';

import { parsePrecondition, parseUuid, versioned } from '../common/http.js';
import { actorContext } from '../common/request-context.js';
import { PocCommandService } from './poc-command.service.js';
import { PocQueryService } from './poc-query.service.js';

type Paginated<T> = Promise<{ data: T[]; meta: PaginationMeta }>;

const idempotencyKeySchema = z
  .string()
  .regex(/^[A-Za-z0-9._-]{1,64}$/, { message: 'must be 1–64 characters of [A-Za-z0-9._-]' });

const commitsQuerySchema = z.strictObject(paginationQuerySchema.shape);

@ApiTags('poc-repositories')
@ApiBearerAuth()
@RequirePermissions('poc:read')
@Controller('poc-repositories')
export class PocRepositoriesController {
  constructor(private readonly queries: PocQueryService) {}

  @Get()
  @ApiOperation({ summary: 'Search discovered PoC repositories' })
  async list(@Query() query: unknown): Paginated<PocRepository> {
    const parsed = parseRequest(listPocRepositoriesQuerySchema, query);
    const { items, total } = await this.queries.listRepositories(parsed);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Get(':repositoryId')
  @ApiOperation({ summary: 'Get a PoC repository with its owner, latest commit and CVE IDs' })
  async get(
    @Res({ passthrough: true }) res: Response,
    @Param('repositoryId') repositoryId: string,
  ): Promise<{ data: PocRepository }> {
    const repository = await this.queries.getRepository(parseUuid(repositoryId, 'repositoryId'));
    return versioned(res, repository, HttpStatus.OK);
  }

  @Get(':repositoryId/commits')
  @ApiOperation({ summary: 'Head commits observed for a repository, newest first' })
  async commits(
    @Param('repositoryId') repositoryId: string,
    @Query() query: unknown,
  ): Paginated<RepositoryCommit> {
    const parsed = parseRequest(commitsQuerySchema, query);
    const { items, total } = await this.queries.listCommits(
      parseUuid(repositoryId, 'repositoryId'),
      parsed,
    );
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }
}

@ApiTags('poc-owners')
@ApiBearerAuth()
@RequirePermissions('poc:read')
@Controller('poc-owners')
export class PocOwnersController {
  constructor(private readonly queries: PocQueryService) {}

  @Get()
  @ApiOperation({ summary: 'Repository owners (GitHub users and organisations)' })
  async list(@Query() query: unknown): Paginated<PocOwner> {
    const parsed = parseRequest(listPocOwnersQuerySchema, query);
    const { items, total } = await this.queries.listOwners(parsed);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Get(':ownerId')
  @ApiOperation({ summary: 'Get a repository owner' })
  async get(@Param('ownerId') ownerId: string): Promise<{ data: PocOwner }> {
    return { data: await this.queries.getOwner(parseUuid(ownerId, 'ownerId')) };
  }
}

@ApiTags('poc-associations')
@ApiBearerAuth()
@RequirePermissions('poc:read')
@Controller('poc-associations')
export class PocAssociationsController {
  constructor(
    private readonly queries: PocQueryService,
    private readonly commands: PocCommandService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Scored CVE associations, highest confidence first' })
  async list(@Query() query: unknown): Paginated<PocAssociation> {
    const parsed = parseRequest(listPocAssociationsQuerySchema, query);
    const { items, total } = await this.queries.listAssociations(parsed);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Post()
  @RequirePermissions('poc:manage')
  @ApiOperation({ summary: 'Associate a known repository with a CVE (confirmed, origin manual)' })
  async create(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Body() body: unknown,
  ): Promise<{ data: PocAssociation }> {
    const association = await this.commands.createAssociation(
      actorContext(req, principal),
      parseRequest(createAssociationRequestSchema, body),
    );
    return versioned(
      res,
      association,
      HttpStatus.CREATED,
      `/api/v1/poc-associations/${association.id}`,
    );
  }

  @Get(':associationId')
  @ApiOperation({ summary: 'Get an association with its signals and penalties' })
  async get(
    @Res({ passthrough: true }) res: Response,
    @Param('associationId') associationId: string,
  ): Promise<{ data: PocAssociation }> {
    const association = await this.queries.getAssociation(
      parseUuid(associationId, 'associationId'),
    );
    return versioned(res, association, HttpStatus.OK);
  }

  @Patch(':associationId')
  @RequirePermissions('poc:manage')
  @ApiOperation({ summary: 'Confirm or reject an association' })
  @ApiHeader({ name: 'If-Match', required: false })
  async review(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('associationId') associationId: string,
    @Body() body: unknown,
    @Headers('if-match') ifMatch: string | undefined,
  ): Promise<{ data: PocAssociation }> {
    const id = parseUuid(associationId, 'associationId');
    const input = parseRequest(reviewAssociationRequestSchema, body);
    const association = await this.commands.reviewAssociation(
      actorContext(req, principal),
      id,
      input,
      parsePrecondition(ifMatch),
    );
    return versioned(res, association, HttpStatus.OK);
  }
}

@ApiTags('poc-artifacts')
@ApiBearerAuth()
@RequirePermissions('poc:read')
@Controller('poc-artifacts')
export class PocArtifactsController {
  constructor(
    private readonly queries: PocQueryService,
    private readonly commands: PocCommandService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Repository snapshots with duplicate links and verification status' })
  async list(
    @Query() query: unknown,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
  ): Paginated<PocArtifact> {
    const parsed = parseRequest(listPocArtifactsQuerySchema, query);
    const { items, total } = await this.queries.listArtifacts(parsed, principal.permissions);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Get(':artifactId')
  @ApiOperation({ summary: 'Get an artifact with its file listing (metadata only)' })
  async get(
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('artifactId') artifactId: string,
  ): Promise<{ data: PocArtifactDetail }> {
    const artifact = await this.queries.getArtifact(
      parseUuid(artifactId, 'artifactId'),
      principal.permissions,
    );
    return versioned(res, artifact, HttpStatus.OK);
  }

  @Get(':artifactId/verification-history')
  @ApiOperation({ summary: 'Verification decisions, newest first' })
  async history(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('artifactId') artifactId: string,
  ): Promise<{ data: VerificationEvent[] }> {
    return {
      data: await this.queries.verificationHistory(
        parseUuid(artifactId, 'artifactId'),
        principal.permissions,
      ),
    };
  }

  @Post(':artifactId/verification')
  @HttpCode(HttpStatus.OK)
  @RequirePermissions('poc:manage')
  @ApiOperation({
    summary: 'Change the verification status (leaving malicious needs quarantine:manage)',
  })
  @ApiHeader({ name: 'If-Match', required: false })
  async changeVerification(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('artifactId') artifactId: string,
    @Body() body: unknown,
    @Headers('if-match') ifMatch: string | undefined,
  ): Promise<{ data: PocArtifact }> {
    const id = parseUuid(artifactId, 'artifactId');
    const input = parseRequest(changeVerificationRequestSchema, body);
    const artifact = await this.commands.changeVerification(
      actorContext(req, principal),
      principal.permissions,
      id,
      input,
      parsePrecondition(ifMatch),
    );
    return versioned(res, artifact, HttpStatus.OK);
  }
}

@ApiTags('poc-references')
@ApiBearerAuth()
@RequirePermissions('poc:read')
@Controller('poc-references')
export class PocReferencesController {
  constructor(private readonly queries: PocQueryService) {}

  @Get()
  @ApiOperation({ summary: 'Public PoC references listed by CVE records' })
  async list(@Query() query: unknown): Paginated<PocReference> {
    const parsed = parseRequest(listPocReferencesQuerySchema, query);
    const { items, total } = await this.queries.listReferences(parsed);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }
}

@ApiTags('poc-discovery')
@ApiBearerAuth()
@RequirePermissions('poc:read')
@Controller()
export class PocDiscoveryController {
  constructor(
    private readonly queries: PocQueryService,
    private readonly commands: PocCommandService,
  ) {}

  @Get('poc-connectors')
  @ApiOperation({ summary: 'Approved discovery connectors and their state' })
  async connectors(): Promise<{ data: PocConnectorStatus[] }> {
    return { data: await this.queries.listConnectors() };
  }

  @Get('poc-discovery-runs')
  @ApiOperation({ summary: 'Discovery log, newest first' })
  async runs(@Query() query: unknown): Paginated<DiscoveryRun> {
    const parsed = parseRequest(listDiscoveryRunsQuerySchema, query);
    const { items, total } = await this.queries.listRuns(parsed);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Get('poc-discovery-runs/:runId')
  @ApiOperation({ summary: 'One discovery run' })
  async run(@Param('runId') runId: string): Promise<{ data: DiscoveryRun }> {
    return { data: await this.queries.getRun(parseUuid(runId, 'runId')) };
  }

  @Post('poc-discovery-runs')
  @HttpCode(HttpStatus.ACCEPTED)
  @RequirePermissions('poc:manage')
  @ApiOperation({
    summary: 'Queue a discovery job (CVE search, recent sweep or repository inspection)',
  })
  @ApiHeader({ name: IDEMPOTENCY_KEY_HEADER, required: false })
  async trigger(
    @Req() req: Request,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Body() body: unknown,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: string | undefined,
  ): Promise<{ data: TriggerDiscoveryResponse }> {
    const input = parseRequest(triggerDiscoveryRequestSchema, body);
    const key =
      idempotencyKey === undefined ? undefined : parseRequest(idempotencyKeySchema, idempotencyKey);
    return { data: await this.commands.triggerDiscovery(actorContext(req, principal), input, key) };
  }
}
