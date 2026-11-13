import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import { getServerBackendUrl } from '@/lib/apiClient';
import { OSS_TOKEN_COOKIE } from '@/lib/auth/cookies';
import {
  clearSession,
  getOidcEndpoints,
  isExpiring,
  isNavigation,
  loginUrl as oidcLoginUrl,
  OIDC_ERROR_PATH,
  OIDC_REFRESH_COOKIE,
  type OidcConfig,
  refreshTokens,
  writeSessionTokens,
} from '@/lib/auth/oidc';

// Paths that don't require authentication in OSS mode.
// `/embed` serves the public website widget (e.g. /embed/dograh-widget.js),
// which must be fetchable without a session cookie so third-party sites can
// embed it — otherwise the middleware 307-redirects the asset to /auth/login.
const PUBLIC_PATHS = ['/auth/login', '/auth/signup', '/embed', '/get-service-key'];

// Paths that don't require authentication in OIDC mode. Sign-in itself happens
// at the provider; the error page is where a failed sign-in comes to rest.
const OIDC_PUBLIC_PATHS = [OIDC_ERROR_PATH, '/embed', '/get-service-key'];

let cachedAuthProvider: string | null = null;
let cachedOidcConfig: OidcConfig | null = null;

async function fetchAuthProvider(): Promise<string> {
  if (cachedAuthProvider) {
    return cachedAuthProvider;
  }

  try {
    const backendUrl = getServerBackendUrl();
    const res = await fetch(`${backendUrl}/api/v1/health`);
    if (res.ok) {
      const data = await res.json();
      // Only cache a DEFINITIVE answer from the backend. Never cache a failure:
      // this is a module-scoped cache with no TTL, so a single early request
      // during container startup (before the api service is reachable) would
      // otherwise poison it to 'local' for the life of the worker — redirecting
      // every Stack user to the local /auth/login form even though the backend
      // reports `stack`.
      cachedOidcConfig =
        data.auth_provider === 'oidc' && data.oidc_issuer && data.oidc_client_id
          ? {
              issuer: data.oidc_issuer as string,
              clientId: data.oidc_client_id as string,
              scopes: (data.oidc_scopes as string) || 'openid profile email',
            }
          : null;
      cachedAuthProvider = (data.auth_provider as string) || 'local';
      return cachedAuthProvider;
    }
  } catch {
    // Backend not reachable — fall through without caching so we retry next request.
  }

  // Provider unknown (backend unreachable). Return a non-'local' sentinel so the
  // middleware does NOT guard/redirect: assuming 'local' here would bounce Stack
  // users to /auth/login. Deliberately not cached — the next request retries.
  return 'unknown';
}

function isPublicPath(pathname: string, publicPaths: string[]): boolean {
  return publicPaths.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

/**
 * OIDC mode: every page needs a session, and server-rendered pages read the
 * access token straight from the cookie. So an expired token is renewed here,
 * before the page runs, and the renewed cookies are handed to this same
 * request as well as to the browser.
 */
async function oidcMiddleware(request: NextRequest): Promise<NextResponse> {
  const { pathname, search } = request.nextUrl;
  if (isPublicPath(pathname, OIDC_PUBLIC_PATHS)) {
    return NextResponse.next();
  }

  const accessToken = request.cookies.get(OSS_TOKEN_COOKIE)?.value;
  if (!isExpiring(accessToken)) {
    return NextResponse.next();
  }

  const refreshToken = request.cookies.get(OIDC_REFRESH_COOKIE)?.value;
  if (refreshToken && cachedOidcConfig) {
    try {
      const tokens = await refreshTokens({
        config: cachedOidcConfig,
        endpoints: await getOidcEndpoints(cachedOidcConfig.issuer),
        refreshToken,
      });
      request.cookies.set(OSS_TOKEN_COOKIE, tokens.accessToken);
      const response = NextResponse.next({
        request: { headers: new Headers(request.headers) },
      });
      writeSessionTokens(response.cookies, request, tokens);
      return response;
    } catch {
      // The provider session is over; fall through to a fresh sign-in.
    }
  }

  // Background fetches (router prefetches, RSC data) cannot follow a redirect
  // to the provider. Tell them the session is gone and let the page navigate.
  const response = isNavigation(request)
    ? NextResponse.redirect(new URL(oidcLoginUrl(pathname + search), request.url))
    : NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  clearSession(response.cookies, request, { keepIdToken: true });
  return response;
}

export async function middleware(request: NextRequest) {
  const authProvider = await fetchAuthProvider();

  if (authProvider === 'oidc') {
    return oidcMiddleware(request);
  }

  // Only handle OSS mode
  if (authProvider !== 'local') {
    return NextResponse.next();
  }

  const token = request.cookies.get(OSS_TOKEN_COOKIE)?.value;
  const { pathname } = request.nextUrl;

  // Allow public paths without auth. Match on a path-segment boundary (exact
  // match or a `/`-delimited subpath) rather than a bare prefix, so a public
  // entry like `/embed` exempts `/embed` and `/embed/...` but NOT sibling
  // routes such as `/embed-admin` — a bare startsWith would let those bypass
  // authentication.
  if (isPublicPath(pathname, PUBLIC_PATHS)) {
    return NextResponse.next();
  }

  // If no token, redirect to login
  if (!token) {
    const loginUrl = new URL('/auth/login', request.url);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

// Configure which routes the middleware runs on
export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - api routes
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public static assets (anything with a file extension, e.g. /dograh-logo.png)
     */
    '/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf)).*)',
  ],
};
