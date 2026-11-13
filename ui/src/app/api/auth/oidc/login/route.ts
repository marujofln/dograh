/*
  Starts an OpenID Connect sign-in: remembers the PKCE verifier, state and
  nonce in a short-lived httpOnly cookie and sends the browser to the provider.

  `?idp=<alias>` picks the upstream identity provider (a customer's own single
  sign-on) when OIDC_IDP_HINT_PARAM is set. The choice is remembered, so a
  later sign-in from this browser goes back to the same one; `?idp=` forgets it.
*/
import { NextRequest, NextResponse } from 'next/server';

import { getOidcConfig } from '@/lib/auth/config';
import {
  buildAuthorizationUrl,
  flowCookieName,
  flowCookieOptions,
  getOidcEndpoints,
  idpCookieOptions,
  idpHintParam,
  isNavigation,
  OIDC_CALLBACK_PATH,
  OIDC_ERROR_PATH,
  OIDC_IDP_COOKIE,
  type OidcFlowState,
  pkceChallenge,
  publicOrigin,
  randomToken,
  safeIdpHint,
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
  const params = request.nextUrl.searchParams;
  const hintParam = idpHintParam();
  const requestedIdp = safeIdpHint(params.get('idp'));
  const forgetIdp = params.has('idp') && !requestedIdp;
  const idp =
    hintParam && !forgetIdp
      ? (requestedIdp ?? safeIdpHint(request.cookies.get(OIDC_IDP_COOKIE)?.value))
      : null;

  try {
    const endpoints = await getOidcEndpoints(config.issuer);
    const flow: OidcFlowState = {
      state: randomToken(),
      nonce: randomToken(),
      verifier: randomToken(48),
      returnTo: safeReturnTo(params.get('returnTo')),
    };

    const response = NextResponse.redirect(
      buildAuthorizationUrl({
        config,
        endpoints,
        redirectUri: `${origin}${OIDC_CALLBACK_PATH}`,
        state: flow.state,
        nonce: flow.nonce,
        challenge: await pkceChallenge(flow.verifier),
        idpHint: hintParam && idp ? { param: hintParam, value: idp } : null,
      }),
    );
    if (hintParam && requestedIdp) {
      response.cookies.set(OIDC_IDP_COOKIE, requestedIdp, idpCookieOptions(request));
    } else if (forgetIdp) {
      response.cookies.set(OIDC_IDP_COOKIE, '', idpCookieOptions(request, 0));
    }
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
