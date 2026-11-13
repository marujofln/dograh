/*
  Hands the current access token to OidcProviderWrapper in the browser,
  renewing it with the refresh token when it is about to expire.
  Returns 401 when there is no session left (the user must sign in again).

  The token is confirmed with the API before it is handed out. An unexpired
  cookie is not proof of a session: it may have been issued by another
  deployment on the same host, or for an organization the user has since left.
*/
import { NextRequest, NextResponse } from 'next/server';

import { getOidcConfig } from '@/lib/auth/config';
import { OSS_TOKEN_COOKIE } from '@/lib/auth/cookies';
import {
  clearSession,
  fetchBackendUser,
  getOidcEndpoints,
  isExpiring,
  OIDC_ID_TOKEN_COOKIE,
  OIDC_REFRESH_COOKIE,
  type OidcTokens,
  refreshTokens,
  tokenExpiresAt,
  writeSessionTokens,
  writeSessionUser,
} from '@/lib/auth/oidc';
import logger from '@/lib/logger';

export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' };

export async function GET(request: NextRequest) {
  const config = await getOidcConfig();
  if (!config) {
    return NextResponse.json({ error: 'Not in OIDC mode' }, { status: 400 });
  }

  const unauthenticated = () => {
    const response = NextResponse.json(
      { error: 'Not authenticated' },
      { status: 401, headers: NO_STORE },
    );
    clearSession(response.cookies, request, { keepIdToken: true });
    return response;
  };

  let accessToken = request.cookies.get(OSS_TOKEN_COOKIE)?.value ?? null;
  const refreshToken = request.cookies.get(OIDC_REFRESH_COOKIE)?.value ?? null;
  const idToken = request.cookies.get(OIDC_ID_TOKEN_COOKIE)?.value ?? null;
  let renewed: OidcTokens | null = null;

  const renew = async (): Promise<boolean> => {
    if (!refreshToken || renewed) {
      return false;
    }
    try {
      renewed = await refreshTokens({
        config,
        endpoints: await getOidcEndpoints(config.issuer),
        refreshToken,
      });
      accessToken = renewed.accessToken;
      return true;
    } catch (error) {
      // The provider session ended (logout elsewhere, idle timeout, revocation).
      logger.info('OIDC session could not be renewed', error);
      return false;
    }
  };

  // `renewed` is assigned inside renew(), which the compiler cannot follow.
  const renewedTokens = () => renewed as OidcTokens | null;
  const currentIdToken = () => renewedTokens()?.idToken ?? idToken;

  if (isExpiring(accessToken) && !(await renew())) {
    return unauthenticated();
  }

  try {
    let result = await fetchBackendUser(accessToken!, currentIdToken());
    // Rejected though unexpired: try once with a token fresh from the provider.
    if (!result.ok && result.status === 401 && (await renew())) {
      result = await fetchBackendUser(accessToken!, currentIdToken());
    }
    if (!result.ok) {
      if (result.status === 401 || result.status === 403) {
        return unauthenticated();
      }
      throw new Error(`API answered ${result.status}`);
    }

    const response = NextResponse.json(
      { token: accessToken, user: result.user, expiresAt: tokenExpiresAt(accessToken) },
      { headers: NO_STORE },
    );
    const tokens = renewedTokens();
    if (tokens) {
      writeSessionTokens(response.cookies, request, tokens);
    }
    writeSessionUser(response.cookies, request, result.user);
    return response;
  } catch (error) {
    // The API being down is not a sign-out: keep the cookies and let the
    // browser retry.
    logger.error('OIDC session could not be confirmed with the API', error);
    return NextResponse.json(
      { error: 'Session could not be confirmed' },
      { status: 503, headers: NO_STORE },
    );
  }
}
