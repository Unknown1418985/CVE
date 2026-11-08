import { NextResponse, type NextRequest } from 'next/server';

import { forwardToGateway } from '@/lib/auth/gateway-proxy';

export const dynamic = 'force-dynamic';

interface Context {
  params: Promise<{ path: string[] }>;
}

async function handle(request: NextRequest, context: Context): Promise<NextResponse> {
  const { path } = await context.params;
  return forwardToGateway(request, path);
}

export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const PATCH = handle;
export const DELETE = handle;
