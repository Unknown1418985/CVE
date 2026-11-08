'use client';

import {
  cveProductAssociationSchema,
  productHistoryEntrySchema,
  productSchema,
  productSummarySchema,
  vendorAnalyticsSchema,
  vendorSchema,
} from '@cve/contracts';

import { apiPath, dataSchema, pageSchema, type QueryParams } from '@/lib/api/client';
import { useApiQuery } from '@/lib/api/hooks';

export function useVendors(query: QueryParams, enabled = true) {
  return useApiQuery({
    path: 'vendors',
    schema: pageSchema(vendorSchema),
    query,
    enabled,
    keepPrevious: true,
  });
}

export function useVendor(vendorId: string) {
  return useApiQuery({ path: apiPath('vendors', vendorId), schema: dataSchema(vendorSchema) });
}

export function useVendorAnalytics(vendorId: string) {
  return useApiQuery({
    path: apiPath('vendors', vendorId, 'analytics'),
    schema: dataSchema(vendorAnalyticsSchema),
    query: { topProducts: 10 },
  });
}

export function useProducts(query: QueryParams, enabled = true) {
  return useApiQuery({
    path: 'products',
    schema: pageSchema(productSummarySchema),
    query,
    enabled,
    keepPrevious: true,
  });
}

export function useProduct(productId: string) {
  return useApiQuery({ path: apiPath('products', productId), schema: dataSchema(productSchema) });
}

export function useProductVulnerabilities(productId: string, query: QueryParams) {
  return useApiQuery({
    path: apiPath('products', productId, 'vulnerabilities'),
    schema: pageSchema(cveProductAssociationSchema),
    query,
    keepPrevious: true,
  });
}

export function useProductHistory(productId: string, query: QueryParams) {
  return useApiQuery({
    path: apiPath('products', productId, 'vulnerability-history'),
    schema: pageSchema(productHistoryEntrySchema),
    query,
    keepPrevious: true,
  });
}

export function useCveAssociations(query: QueryParams, enabled = true) {
  return useApiQuery({
    path: 'cve-associations',
    schema: pageSchema(cveProductAssociationSchema),
    query,
    enabled,
    keepPrevious: true,
  });
}
