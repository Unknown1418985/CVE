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
} from '@nestjs/common';
import { ApiBearerAuth, ApiHeader, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';
import { z } from 'zod';

import { CurrentPrincipal, RequirePermissions, type AuthenticatedPrincipal } from '@cve/auth';
import {
  buildPaginationMeta,
  IDEMPOTENCY_KEY_HEADER,
  intelligenceSourceSchema,
  listSyncRunsQuerySchema,
  triggerSyncRequestSchema,
  type PaginationMeta,
  type SourceStatus,
  type SyncRun,
  type SyncRunDetail,
  type TriggerSyncResponse,
} from '@cve/contracts';
import { parseRequest } from '@cve/shared';

import { requestContext } from './request-context.js';
import { SyncService } from './sync.service.js';

const idempotencyKeySchema = z
  .string()
  .regex(/^[A-Za-z0-9._-]{1,64}$/, { message: 'must be 1–64 characters of [A-Za-z0-9._-]' });

@ApiTags('data-sources')
@ApiBearerAuth()
@RequirePermissions('data-source:read')
@Controller('sources')
export class SourcesController {
  constructor(private readonly sync: SyncService) {}

  @Get()
  @ApiOperation({ summary: 'List intelligence sources with configuration, terms and sync state' })
  async list(): Promise<{ data: SourceStatus[] }> {
    return { data: await this.sync.listSources() };
  }

  @Get(':source')
  @ApiOperation({ summary: 'Get one intelligence source' })
  async get(@Param('source') source: string): Promise<{ data: SourceStatus }> {
    return { data: await this.sync.getSource(parseRequest(intelligenceSourceSchema, source)) };
  }

  @Post(':source/sync')
  @HttpCode(HttpStatus.ACCEPTED)
  @RequirePermissions('data-source:manage')
  @ApiOperation({ summary: 'Queue a synchronisation (resumes a recent failed run unless fresh)' })
  @ApiHeader({ name: IDEMPOTENCY_KEY_HEADER, required: false })
  async trigger(
    @Req() req: Request,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('source') source: string,
    @Body() body: unknown,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: string | undefined,
  ): Promise<{ data: TriggerSyncResponse }> {
    const parsedSource = parseRequest(intelligenceSourceSchema, source);
    const input = parseRequest(triggerSyncRequestSchema, body ?? {});
    const key =
      idempotencyKey === undefined ? undefined : parseRequest(idempotencyKeySchema, idempotencyKey);
    return {
      data: await this.sync.trigger(
        parsedSource,
        { fresh: input.fresh, idempotencyKey: key },
        requestContext(req, principal),
      ),
    };
  }
}

@ApiTags('data-sources')
@ApiBearerAuth()
@RequirePermissions('data-source:read')
@Controller('sync-runs')
export class SyncRunsController {
  constructor(private readonly sync: SyncService) {}

  @Get()
  @ApiOperation({ summary: 'Synchronisation history, newest first' })
  async list(@Query() query: unknown): Promise<{ data: SyncRun[]; meta: PaginationMeta }> {
    const parsed = parseRequest(listSyncRunsQuerySchema, query);
    const { items, total } = await this.sync.listRuns(parsed);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Get(':runId')
  @ApiOperation({ summary: 'One run with its issues' })
  async get(@Param('runId') runId: string): Promise<{ data: SyncRunDetail }> {
    return { data: await this.sync.getRun(parseRequest(z.uuid(), runId)) };
  }

  @Post(':runId/retry')
  @HttpCode(HttpStatus.ACCEPTED)
  @RequirePermissions('data-source:manage')
  @ApiOperation({ summary: 'Retry a failed or abandoned run from its checkpoint' })
  async retry(
    @Req() req: Request,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('runId') runId: string,
  ): Promise<{ data: TriggerSyncResponse }> {
    return {
      data: await this.sync.retry(parseRequest(z.uuid(), runId), requestContext(req, principal)),
    };
  }
}
