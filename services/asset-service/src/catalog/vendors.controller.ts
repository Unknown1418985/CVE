import {
  Body,
  Controller,
  Delete,
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

import { CurrentPrincipal, RequirePermissions, type AuthenticatedPrincipal } from '@cve/auth';
import {
  buildPaginationMeta,
  createVendorRequestSchema,
  listProductsQuerySchema,
  listVendorsQuerySchema,
  updateVendorRequestSchema,
  vendorAnalyticsQuerySchema,
  type PaginationMeta,
  type ProductSummary,
  type Vendor,
  type VendorAnalytics,
} from '@cve/contracts';
import { parseRequest } from '@cve/shared';

import { VendorAnalyticsService } from '../analytics/vendor-analytics.service.js';
import { parsePrecondition, parseUuid, versioned } from '../common/http.js';
import { actorContext } from '../common/request-context.js';
import { ProductsService } from './products.service.js';
import { VendorsService } from './vendors.service.js';

const vendorProductsQuerySchema = listProductsQuerySchema.omit({ vendorId: true, vendor: true });

@ApiTags('vendors')
@ApiBearerAuth()
@RequirePermissions('asset:read')
@Controller('vendors')
export class VendorsController {
  constructor(
    private readonly vendors: VendorsService,
    private readonly products: ProductsService,
    private readonly analytics: VendorAnalyticsService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Search vendors by name or slug, with sorting and pagination' })
  async list(@Query() query: unknown): Promise<{ data: Vendor[]; meta: PaginationMeta }> {
    const parsed = parseRequest(listVendorsQuerySchema, query);
    const { items, total } = await this.vendors.list(parsed);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Post()
  @RequirePermissions('asset:manage')
  @ApiOperation({ summary: 'Create a vendor (409 if the slug exists)' })
  async create(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Body() body: unknown,
  ): Promise<{ data: Vendor }> {
    const vendor = await this.vendors.create(
      actorContext(req, principal),
      parseRequest(createVendorRequestSchema, body),
    );
    return versioned(res, vendor, HttpStatus.CREATED, `/api/v1/vendors/${vendor.id}`);
  }

  @Get(':vendorId')
  @ApiOperation({ summary: 'Get a vendor' })
  async get(
    @Res({ passthrough: true }) res: Response,
    @Param('vendorId') vendorId: string,
  ): Promise<{ data: Vendor }> {
    const vendor = await this.vendors.get(parseUuid(vendorId, 'vendorId'));
    return versioned(res, vendor, HttpStatus.OK);
  }

  @Patch(':vendorId')
  @RequirePermissions('asset:manage')
  @ApiOperation({ summary: 'Update a vendor; a discovered vendor becomes curated' })
  @ApiHeader({ name: 'If-Match', required: false })
  async update(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('vendorId') vendorId: string,
    @Body() body: unknown,
    @Headers('if-match') ifMatch: string | undefined,
  ): Promise<{ data: Vendor }> {
    const id = parseUuid(vendorId, 'vendorId');
    const patch = parseRequest(updateVendorRequestSchema, body);
    const { vendor } = await this.vendors.update(
      actorContext(req, principal),
      id,
      patch,
      parsePrecondition(ifMatch),
    );
    return versioned(res, vendor, HttpStatus.OK);
  }

  @Delete(':vendorId')
  @RequirePermissions('asset:manage')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete a vendor without products' })
  @ApiHeader({ name: 'If-Match', required: false })
  async delete(
    @Req() req: Request,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('vendorId') vendorId: string,
    @Headers('if-match') ifMatch: string | undefined,
  ): Promise<void> {
    const id = parseUuid(vendorId, 'vendorId');
    await this.vendors.delete(actorContext(req, principal), id, parsePrecondition(ifMatch));
  }

  @Get(':vendorId/products')
  @ApiOperation({ summary: "List a vendor's products" })
  async listProducts(
    @Param('vendorId') vendorId: string,
    @Query() query: unknown,
  ): Promise<{ data: ProductSummary[]; meta: PaginationMeta }> {
    const id = parseUuid(vendorId, 'vendorId');
    const parsed = parseRequest(vendorProductsQuerySchema, query);
    await this.vendors.get(id);
    const { items, total } = await this.products.list({ ...parsed, vendorId: id });
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Get(':vendorId/analytics')
  @ApiOperation({ summary: 'Vulnerability analytics of a vendor (severity, KEV, CVSS, EPSS)' })
  async vendorAnalytics(
    @Param('vendorId') vendorId: string,
    @Query() query: unknown,
  ): Promise<{ data: VendorAnalytics }> {
    const id = parseUuid(vendorId, 'vendorId');
    const { topProducts } = parseRequest(vendorAnalyticsQuerySchema, query);
    return { data: await this.analytics.forVendor(id, topProducts) };
  }
}
