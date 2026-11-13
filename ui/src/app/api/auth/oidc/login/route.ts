/*
  Starts an OpenID Connect sign-in: remembers the PKCE verifier, state and
  nonce in a short-lived httpOnly cookie and sends the browser to the provider.
*/
import { NextRequest, NextResponse } from 'next/server';

import { getOidcConfig } from '@/lib/auth/config';
import {
  buildAuthorizationUrl,
  flowCookieName,
  flowCookieOptions,
  getOidcEndpoints,
  isNavigation,
  OIDC_CALLBACK_PATH,
  OIDC_ERROR_PATH,
  type OidcFlowState,
  pkceChallenge,
  publicOrigin,
  randomToken,
  safeReturnTo,
} from '@/lib/auth/oidc';
import logger from '@/lib/logger';

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  const config = await getOidcConfig();
  if (!config) {
    return NextResponse.json({ error: 'Not in OIDC mode' }, { status: 400 });
  }

  if (!isNavigation(request)) {
    return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
  }

  const origin = publicOrigin(request);
  try {
    const endpoints = await getOidcEndpoints(config.issuer);
    const flow: OidcFlowState = {
      state: randomToken(),
      nonce: randomToken(),
      verifier: randomToken(48),
      returnTo: safeReturnTo(request.nextUrl.searchParams.get('returnTo')),
    };

    const response = NextResponse.redirect(
      buildAuthorizationUrl({
        config,
        endpoints,
        redirectUri: `${origin}${OIDC_CALLBACK_PATH}`,
        state: flow.state,
        nonce: flow.nonce,
        challenge: await pkceChallenge(flow.verifier),
      }),
    );
    response.cookies.set(
      flowCookieName(flow.state)!,
      JSON.stringify(flow),
      flowCookieOptions(request),
    );
    return response;
  } catch (error) {
    logger.error('OIDC sign-in could not start', error);
    return NextResponse.redirect(`${origin}${OIDC_ERROR_PATH}?reason=provider`);
  }
}
