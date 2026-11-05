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
  Put,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { ApiBearerAuth, ApiHeader, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { Request, Response } from 'express';

import { CurrentPrincipal, RequirePermissions, type AuthenticatedPrincipal } from '@cve/auth';
import {
  buildPaginationMeta,
  createProductRequestSchema,
  cveIdSchema,
  listProductsQuerySchema,
  listProductVulnerabilitiesQuerySchema,
  productCpeInputSchema,
  productHistoryQuerySchema,
  productIdentifierInputSchema,
  setManualAssociationRequestSchema,
  updateProductRequestSchema,
  type CveProductAssociation,
  type PaginationMeta,
  type Product,
  type ProductHistoryEntry,
  type ProductSummary,
} from '@cve/contracts';
import { parseRequest } from '@cve/shared';

import { AssociationsService } from '../associations/associations.service.js';
import { parsePrecondition, parseUuid, versioned } from '../common/http.js';
import { actorContext } from '../common/request-context.js';
import { ProductsService } from './products.service.js';

@ApiTags('products')
@ApiBearerAuth()
@RequirePermissions('asset:read')
@Controller('products')
export class ProductsController {
  constructor(
    private readonly products: ProductsService,
    private readonly associations: AssociationsService,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'Search products by name, vendor, type, CPE name or identifier, with pagination',
  })
  async list(@Query() query: unknown): Promise<{ data: ProductSummary[]; meta: PaginationMeta }> {
    const parsed = parseRequest(listProductsQuerySchema, query);
    const { items, total } = await this.products.list(parsed);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Post()
  @RequirePermissions('asset:manage')
  @ApiOperation({ summary: 'Create a product with optional CPE names and identifiers' })
  async create(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Body() body: unknown,
  ): Promise<{ data: Product }> {
    const product = await this.products.create(
      actorContext(req, principal),
      parseRequest(createProductRequestSchema, body),
    );
    return versioned(res, product, HttpStatus.CREATED, `/api/v1/products/${product.id}`);
  }

  @Get(':productId')
  @ApiOperation({ summary: 'Get a product with its CPE names and identifiers' })
  async get(
    @Res({ passthrough: true }) res: Response,
    @Param('productId') productId: string,
  ): Promise<{ data: Product }> {
    return versioned(
      res,
      await this.products.get(parseUuid(productId, 'productId')),
      HttpStatus.OK,
    );
  }

  @Patch(':productId')
  @RequirePermissions('asset:manage')
  @ApiOperation({ summary: 'Update a product; a discovered product becomes curated' })
  @ApiHeader({ name: 'If-Match', required: false })
  async update(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('productId') productId: string,
    @Body() body: unknown,
    @Headers('if-match') ifMatch: string | undefined,
  ): Promise<{ data: Product }> {
    const id = parseUuid(productId, 'productId');
    const patch = parseRequest(updateProductRequestSchema, body);
    const { product } = await this.products.update(
      actorContext(req, principal),
      id,
      patch,
      parsePrecondition(ifMatch),
    );
    return versioned(res, product, HttpStatus.OK);
  }

  @Delete(':productId')
  @RequirePermissions('asset:manage')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete a product without CVE associations' })
  @ApiHeader({ name: 'If-Match', required: false })
  async delete(
    @Req() req: Request,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('productId') productId: string,
    @Headers('if-match') ifMatch: string | undefined,
  ): Promise<void> {
    const id = parseUuid(productId, 'productId');
    await this.products.delete(actorContext(req, principal), id, parsePrecondition(ifMatch));
  }

  @Post(':productId/cpes')
  @RequirePermissions('asset:manage')
  @ApiOperation({ summary: 'Register a CPE 2.3 name (409 if another product has it)' })
  async addCpe(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('productId') productId: string,
    @Body() body: unknown,
  ): Promise<{ data: Product }> {
    const id = parseUuid(productId, 'productId');
    const input = parseRequest(productCpeInputSchema, body);
    const { product, changed } = await this.products.addCpe(
      actorContext(req, principal),
      id,
      input,
    );
    return versioned(res, product, changed ? HttpStatus.CREATED : HttpStatus.OK);
  }

  @Delete(':productId/cpes/:cpeId')
  @RequirePermissions('asset:manage')
  @ApiOperation({ summary: 'Remove a CPE name from a product' })
  async removeCpe(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('productId') productId: string,
    @Param('cpeId') cpeId: string,
  ): Promise<{ data: Product }> {
    const product = await this.products.removeCpe(
      actorContext(req, principal),
      parseUuid(productId, 'productId'),
      parseUuid(cpeId, 'cpeId'),
    );
    return versioned(res, product, HttpStatus.OK);
  }

  @Post(':productId/identifiers')
  @RequirePermissions('asset:manage')
  @ApiOperation({ summary: 'Add a product identifier such as a Package URL or SWID tag ID' })
  async addIdentifier(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('productId') productId: string,
    @Body() body: unknown,
  ): Promise<{ data: Product }> {
    const id = parseUuid(productId, 'productId');
    const input = parseRequest(productIdentifierInputSchema, body);
    const { product, changed } = await this.products.addIdentifier(
      actorContext(req, principal),
      id,
      input,
    );
    return versioned(res, product, changed ? HttpStatus.CREATED : HttpStatus.OK);
  }

  @Delete(':productId/identifiers/:identifierId')
  @RequirePermissions('asset:manage')
  @ApiOperation({ summary: 'Remove a product identifier' })
  async removeIdentifier(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('productId') productId: string,
    @Param('identifierId') identifierId: string,
  ): Promise<{ data: Product }> {
    const product = await this.products.removeIdentifier(
      actorContext(req, principal),
      parseUuid(productId, 'productId'),
      parseUuid(identifierId, 'identifierId'),
    );
    return versioned(res, product, HttpStatus.OK);
  }

  @Get(':productId/vulnerabilities')
  @ApiOperation({
    summary: 'CVEs associated with a product, with version ranges and CVE facts',
  })
  async vulnerabilities(
    @Param('productId') productId: string,
    @Query() query: unknown,
  ): Promise<{ data: CveProductAssociation[]; meta: PaginationMeta }> {
    const id = parseUuid(productId, 'productId');
    const parsed = parseRequest(listProductVulnerabilitiesQuerySchema, query);
    const { items, total } = await this.associations.listForProduct(id, parsed);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Get(':productId/vulnerability-history')
  @ApiOperation({ summary: 'Timeline of association changes (added, changed, withdrawn)' })
  async history(
    @Param('productId') productId: string,
    @Query() query: unknown,
  ): Promise<{ data: ProductHistoryEntry[]; meta: PaginationMeta }> {
    const id = parseUuid(productId, 'productId');
    const parsed = parseRequest(productHistoryQuerySchema, query);
    const { items, total } = await this.associations.history(id, parsed);
    return { data: items, meta: buildPaginationMeta(parsed, total) };
  }

  @Put(':productId/vulnerabilities/:cveId')
  @RequirePermissions('asset:manage')
  @ApiOperation({ summary: 'Set the analyst-maintained association of a CVE with the product' })
  async setManual(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('productId') productId: string,
    @Param('cveId') cveId: string,
    @Body() body: unknown,
  ): Promise<{ data: CveProductAssociation }> {
    const id = parseUuid(productId, 'productId');
    const cve = parseRequest(cveIdSchema, cveId);
    const input = parseRequest(setManualAssociationRequestSchema, body);
    const { association, created } = await this.associations.setManual(
      actorContext(req, principal),
      id,
      cve,
      input,
    );
    res.status(created ? HttpStatus.CREATED : HttpStatus.OK);
    return { data: association };
  }

  @Delete(':productId/vulnerabilities/:cveId')
  @RequirePermissions('asset:manage')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Withdraw the analyst-maintained association (history is kept)' })
  async withdrawManual(
    @Req() req: Request,
    @CurrentPrincipal() principal: AuthenticatedPrincipal,
    @Param('productId') productId: string,
    @Param('cveId') cveId: string,
  ): Promise<void> {
    await this.associations.withdrawManual(
      actorContext(req, principal),
      parseUuid(productId, 'productId'),
      parseRequest(cveIdSchema, cveId),
    );
  }
}
