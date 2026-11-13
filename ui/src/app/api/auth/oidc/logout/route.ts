/*
  Ends the session: clears the cookies and points the browser at the
  provider's end-session endpoint, so the single sign-on session ends too.
  POST returns the URL (for the app); GET redirects (for the error page link).
*/
import { NextRequest, NextResponse } from 'next/server';

import { getOidcConfig } from '@/lib/auth/config';
import {
  buildLogoutUrl,
  clearSession,
  getOidcEndpoints,
  OIDC_ID_TOKEN_COOKIE,
  publicOrigin,
} from '@/lib/auth/oidc';
import logger from '@/lib/logger';

export const dynamic = 'force-dynamic';

async function resolveLogoutUrl(request: NextRequest): Promise<string> {
  const home = `${publicOrigin(request)}/`;
  const config = await getOidcConfig();
  if (!config) {
    return home;
  }
  try {
    return buildLogoutUrl({
      config,
      endpoints: await getOidcEndpoints(config.issuer),
      idToken: request.cookies.get(OIDC_ID_TOKEN_COOKIE)?.value ?? null,
      postLogoutRedirectUri: home,
    });
  } catch (error) {
    // The local session still ends even if the provider cannot be reached.
    logger.error('OIDC logout URL could not be resolved', error);
    return home;
  }
}

export async function POST(request: NextRequest) {
  const logoutUrl = await resolveLogoutUrl(request);
  const response = NextResponse.json({ success: true, logoutUrl });
  clearSession(response.cookies, request);
  return response;
}

export async function GET(request: NextRequest) {
  const response = NextResponse.redirect(await resolveLogoutUrl(request));
  clearSession(response.cookies, request);
  return response;
}
