import { Controller, Get, Inject, NotFoundException, Param, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';

import { RequirePermissions } from '@cve/auth';
import {
  buildPaginationMeta,
  listAuditEventsQuerySchema,
  type AuditEvent,
  type PaginationMeta,
} from '@cve/contracts';
import { parseRequest } from '@cve/shared';

import { AUDIT_REPOSITORY, type AuditRepository } from '../persistence/ports.js';

@ApiTags('audit')
@ApiBearerAuth()
@RequirePermissions('audit:read')
@Controller('audit-logs')
export class AuditController {
  constructor(@Inject(AUDIT_REPOSITORY) private readonly repository: AuditRepository) {}

  @Get()
  @ApiOperation({ summary: 'Search the audit log (newest first)' })
  async list(@Query() query: unknown): Promise<{ data: AuditEvent[]; meta: PaginationMeta }> {
    const parsed = parseRequest(listAuditEventsQuerySchema, query);
    const { items, total } = await this.repository.list(parsed);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get one audit entry' })
  async get(@Param('id') id: string): Promise<{ data: AuditEvent }> {
    const event = await this.repository.find(parseRequest(z.uuid(), id));
    if (!event) throw new NotFoundException('Audit entry not found');
    return { data: event };
  }
}
