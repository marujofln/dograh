/*
  Finishes an OpenID Connect sign-in: checks state and nonce, exchanges the
  code, confirms the access token with the API and stores the session.
*/
import { NextRequest, NextResponse } from 'next/server';

import { getOidcConfig } from '@/lib/auth/config';
import { sessionCookieOptions } from '@/lib/auth/cookies';
import {
  clearSession,
  decodeJwtPayload,
  exchangeCode,
  fetchBackendUser,
  flowCookieName,
  flowCookieOptions,
  getOidcEndpoints,
  OIDC_CALLBACK_PATH,
  OIDC_ERROR_PATH,
  OIDC_ID_TOKEN_COOKIE,
  parseFlowCookie,
  publicOrigin,
  writeSessionTokens,
  writeSessionUser,
} from '@/lib/auth/oidc';
import logger from '@/lib/logger';

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  const config = await getOidcConfig();
  if (!config) {
    return NextResponse.json({ error: 'Not in OIDC mode' }, { status: 400 });
  }

  const origin = publicOrigin(request);
  const params = request.nextUrl.searchParams;
  const state = params.get('state');
  // The flow cookie is looked up by the returned state, so a response can only
  // ever be matched with the attempt that produced it.
  const flowCookie = state ? flowCookieName(state) : null;
  const endFlow = (response: NextResponse) => {
    if (flowCookie) {
      response.cookies.set(flowCookie, '', flowCookieOptions(request, 0));
    }
  };

  const fail = (reason: string, idToken: string | null = null) => {
    const response = NextResponse.redirect(`${origin}${OIDC_ERROR_PATH}?reason=${reason}`);
    endFlow(response);
    // A failed sign-in must not leave a previous session behind. Keep only the
    // ID token, so the error page can end the provider session on sign-out.
    clearSession(response.cookies, request, { keepIdToken: true });
    if (idToken) {
      response.cookies.set(OIDC_ID_TOKEN_COOKIE, idToken, sessionCookieOptions(request, 600));
    }
    return response;
  };

  const flow = flowCookie
    ? parseFlowCookie(request.cookies.get(flowCookie)?.value)
    : null;
  // No cookie, or a state that is not ours: this response was not started by
  // this browser (or was replayed). Nothing from it may be trusted.
  if (!flow || !state || state !== flow.state) {
    return fail('state');
  }
  if (params.get('error')) {
    logger.warn('OIDC provider returned an error', params.get('error'));
    return fail('provider');
  }
  const code = params.get('code');
  if (!code) {
    return fail('provider');
  }

  try {
    const endpoints = await getOidcEndpoints(config.issuer);
    const tokens = await exchangeCode({
      config,
      endpoints,
      code,
      verifier: flow.verifier,
      redirectUri: `${origin}${OIDC_CALLBACK_PATH}`,
    });

    // The ID token came straight from the token endpoint, so its nonce ties
    // this response to the request this browser started.
    const nonce = tokens.idToken ? decodeJwtPayload(tokens.idToken)?.nonce : null;
    if (nonce !== flow.nonce) {
      return fail('state');
    }

    const result = await fetchBackendUser(tokens.accessToken, tokens.idToken);
    if (!result.ok) {
      logger.warn('API rejected the OIDC access token', result.status);
      // 403: a genuine token the API cannot scope to exactly one organization.
      return fail(result.status === 403 ? 'organization' : 'rejected', tokens.idToken);
    }

    const response = NextResponse.redirect(`${origin}${flow.returnTo}`);
    endFlow(response);
    writeSessionTokens(response.cookies, request, tokens);
    writeSessionUser(response.cookies, request, result.user);
    return response;
  } catch (error) {
    logger.error('OIDC sign-in failed', error);
    return fail('provider');
  }
}
