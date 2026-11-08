import { NextResponse, type NextRequest } from 'next/server';

const SESSION_COOKIE = 'cve_session';

/**
 * Sends visitors without a session cookie to the sign-in flow, keeping the page they asked
 * for. The cookie's contents are verified by the platform layout and by the BFF proxy.
 */
export function proxy(request: NextRequest): NextResponse {
  if (request.cookies.get(SESSION_COOKIE)?.value) return NextResponse.next();
  const login = request.nextUrl.clone();
  login.pathname = '/session/login';
  login.search = '';
  login.searchParams.set('returnTo', `${request.nextUrl.pathname}${request.nextUrl.search}`);
  return NextResponse.redirect(login);
}

export const config = {
  // Every page except the sign-in flow, the BFF proxy, health checks and static assets.
  matcher: ['/((?!session/|signed-out|bff/|api/health|_next/|favicon\\.ico).*)'],
};
