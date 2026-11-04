import { Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import type { Request } from 'express';

import { getRequestPrincipal } from '@cve/auth';

/**
 * Rate limits per authenticated user (so users behind one NAT do not share a budget, and a
 * stolen token cannot be spread across IPs), falling back to the client IP for anonymous calls.
 * Runs after authentication; Nginx `limit_req` additionally caps every client IP.
 */
@Injectable()
export class UserThrottlerGuard extends ThrottlerGuard {
  protected override getTracker(req: Record<string, unknown>): Promise<string> {
    const request = req as unknown as Request;
    const principal = getRequestPrincipal(request);
    return Promise.resolve(
      principal ? `user:${principal.subject}` : `ip:${request.ip ?? 'unknown'}`,
    );
  }
}
