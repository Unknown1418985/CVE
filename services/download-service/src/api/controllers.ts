import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { ApiBearerAuth, ApiHeader, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request, Response } from 'express';

import { CurrentPrincipal, RequirePermissions, type AuthenticatedPrincipal } from '@cve/auth';
import {
  buildPaginationMeta,
  changeLifecycleRequestSchema,
  createDownloadRequestSchema,
  listDownloadArtifactsQuerySchema,
  listDownloadRequestsQuerySchema,
  rescanRequestSchema,
  type CreateDownloadResponse,
  type DetectedFileType,
  type DownloadArtifact,
  type DownloadArtifactDetail,
  type DownloadRequest,
  type DownloadRequestDetail,
  type DownloadSourceStatus,
  type LifecycleEvent,
  type PaginationMeta,
  type ScanResult,
} from '@cve/contracts';
import { parseRequest } from '@cve/shared';

import { parsePrecondition, parseUuid, versioned } from '../common/http.js';
import { actorContext } from '../common/request-context.js';
import { FILE_TYPE_EXTENSION } from '../domain/file-type.js';
import { DownloadCommandService } from './download-command.service.js';
import { DownloadQueryService } from './download-query.service.js';

type Paginated<T> = Promise<{ data: T[]; meta: PaginationMeta }>;

@ApiTags('download-sources')
@ApiBearerAuth()
@RequirePermissions('download:read')
@Controller('download-sources')
export class DownloadSourcesController {
  constructor(private readonly queries: DownloadQueryService) {}

  @Get()
  @ApiOperation({ summary: 'Approved download sources, allowlists and limits' })
  list(): { data: DownloadSourceStatus[] } {
    return { data: this.queries.listSources() };
  }
}

@ApiTags('download-requests')
@ApiBearerAuth()
@RequirePermissions('download:read')
@Controller('download-requests')
export class DownloadRequestsController {
  constructor(
    private readonly queries: DownloadQueryService,
    private readonly commands: DownloadCommandService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Download requests (scheduling and history)' })
  async list(@Query() query: unknown): Paginated<DownloadRequest> {
    const parsed = parseRequest(listDownloadRequestsQuerySchema, query);
    const { items, total } = await this.queries.listRequests(parsed);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Post()
  @RequirePermissions('download:schedule')
  @ApiOperation({
    summary: 'Schedule a download from an approved source (idempotent per canonical URL)',
  })
  async create(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Body() body: unknown,
  ): Promise<{ data: CreateDownloadResponse }> {
    const result = await this.commands.createRequest(
      actorContext(req, principal),
      parseRequest(createDownloadRequestSchema, body),
    );
    res.status(result.created ? HttpStatus.CREATED : HttpStatus.OK);
    res.setHeader('Location', `/api/v1/download-requests/${result.request.id}`);
    res.setHeader('Cache-Control', 'no-store');
    return { data: result };
  }

  @Get(':requestId')
  @ApiOperation({ summary: 'A download request with every attempt and its hop chain' })
  async get(
    @Res({ passthrough: true }) res: Response,
    @Param('requestId') requestId: string,
  ): Promise<{ data: DownloadRequestDetail }> {
    const request = await this.queries.getRequest(parseUuid(requestId, 'requestId'));
    return versioned(res, request, HttpStatus.OK);
  }

  @Post(':requestId/retry')
  @HttpCode(HttpStatus.OK)
  @RequirePermissions('download:schedule')
  @ApiOperation({ summary: 'Retry a failed, rejected or cancelled request' })
  @ApiHeader({ name: 'If-Match', required: false })
  async retry(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('requestId') requestId: string,
    @Headers('if-match') ifMatch: string | undefined,
  ): Promise<{ data: DownloadRequest }> {
    const request = await this.commands.retryRequest(
      actorContext(req, principal),
      parseUuid(requestId, 'requestId'),
      parsePrecondition(ifMatch),
    );
    return versioned(res, request, HttpStatus.OK);
  }

  @Post(':requestId/cancel')
  @HttpCode(HttpStatus.OK)
  @RequirePermissions('download:schedule')
  @ApiOperation({ summary: 'Cancel a pending request' })
  @ApiHeader({ name: 'If-Match', required: false })
  async cancel(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('requestId') requestId: string,
    @Headers('if-match') ifMatch: string | undefined,
  ): Promise<{ data: DownloadRequest }> {
    const request = await this.commands.cancelRequest(
      actorContext(req, principal),
      parseUuid(requestId, 'requestId'),
      parsePrecondition(ifMatch),
    );
    return versioned(res, request, HttpStatus.OK);
  }
}

@ApiTags('download-artifacts')
@ApiBearerAuth()
@RequirePermissions('download:read')
@Controller('download-artifacts')
export class DownloadArtifactsController {
  constructor(
    private readonly queries: DownloadQueryService,
    private readonly commands: DownloadCommandService,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'Stored artifacts (quarantined ones only with quarantine:read)',
  })
  async list(
    @Query() query: unknown,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
  ): Paginated<DownloadArtifact> {
    const parsed = parseRequest(listDownloadArtifactsQuerySchema, query);
    const { items, total } = await this.queries.listArtifacts(parsed, principal.permissions);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Get(':artifactId')
  @ApiOperation({ summary: 'An artifact with its provenance and latest scan' })
  async get(
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('artifactId') artifactId: string,
  ): Promise<{ data: DownloadArtifactDetail }> {
    const artifact = await this.queries.getArtifact(
      parseUuid(artifactId, 'artifactId'),
      principal.permissions,
    );
    return versioned(res, artifact, HttpStatus.OK);
  }

  @Get(':artifactId/scans')
  @RequirePermissions('quarantine:read')
  @ApiOperation({ summary: 'Scanner results, newest first' })
  async scans(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('artifactId') artifactId: string,
  ): Promise<{ data: ScanResult[] }> {
    return {
      data: await this.queries.scanHistory(
        parseUuid(artifactId, 'artifactId'),
        principal.permissions,
      ),
    };
  }

  @Get(':artifactId/lifecycle-history')
  @ApiOperation({ summary: 'Lifecycle decisions, newest first' })
  async history(
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('artifactId') artifactId: string,
  ): Promise<{ data: LifecycleEvent[] }> {
    return {
      data: await this.queries.lifecycleHistory(
        parseUuid(artifactId, 'artifactId'),
        principal.permissions,
      ),
    };
  }

  @Post(':artifactId/rescan')
  @HttpCode(HttpStatus.ACCEPTED)
  @RequirePermissions('quarantine:manage')
  @ApiOperation({ summary: 'Scan the artifact again (e.g. after a signature update)' })
  async rescan(
    @Param('artifactId') artifactId: string,
    @Body() body: unknown,
  ): Promise<{ data: { queued: boolean } }> {
    return {
      data: await this.commands.rescan(
        parseUuid(artifactId, 'artifactId'),
        parseRequest(rescanRequestSchema, body),
      ),
    };
  }

  @Post(':artifactId/lifecycle')
  @HttpCode(HttpStatus.OK)
  @RequirePermissions('quarantine:manage')
  @ApiOperation({ summary: 'Release, reject or re-quarantine an artifact' })
  @ApiHeader({ name: 'If-Match', required: false })
  async changeLifecycle(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('artifactId') artifactId: string,
    @Body() body: unknown,
    @Headers('if-match') ifMatch: string | undefined,
  ): Promise<{ data: DownloadArtifact }> {
    const artifact = await this.commands.changeLifecycle(
      actorContext(req, principal),
      parseUuid(artifactId, 'artifactId'),
      parseRequest(changeLifecycleRequestSchema, body),
      parsePrecondition(ifMatch),
    );
    return versioned(res, artifact, HttpStatus.OK);
  }

  /**
   * Streams a released artifact as an opaque attachment. Never previewed: octet-stream,
   * `nosniff`, a sandboxing CSP and a generated file name.
   */
  @Get(':artifactId/content')
  @RequirePermissions('artifact:download')
  @ApiOperation({ summary: 'Download a released artifact (attachment, never rendered)' })
  async content(
    @Req() req: Request,
    @Res() res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('artifactId') artifactId: string,
  ): Promise<void> {
    const controller = new AbortController();
    req.on('close', () => {
      controller.abort();
    });
    const { artifact, body } = await this.commands.openContent(
      parseUuid(artifactId, 'artifactId'),
      principal.permissions,
      controller.signal,
    );
    const extension = FILE_TYPE_EXTENSION[artifact.detectedType as DetectedFileType];
    res.status(HttpStatus.OK);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', String(artifact.sizeBytes));
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="artifact-${artifact.id}${extension}"`,
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader(
      'Repr-Digest',
      `sha-256=:${Buffer.from(artifact.sha256, 'hex').toString('base64')}:`,
    );
    res.setHeader('X-Artifact-SHA256', artifact.sha256);
    body.on('error', () => {
      res.destroy();
    });
    body.pipe(res);
  }
}
