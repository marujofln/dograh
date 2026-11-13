// @vitest-environment node
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  buildAuthorizationUrl,
  buildLogoutUrl,
  clearOidcEndpointCache,
  decodeJwtPayload,
  getOidcEndpoints,
  isExpiring,
  loginUrl,
  parseFlowCookie,
  pkceChallenge,
  publicOrigin,
  randomToken,
  refreshTokens,
  safeReturnTo,
  tokenExpiresAt,
} from './oidc';

const ISSUER = 'https://idp.example.test/realms/platform';
const CONFIG = { issuer: ISSUER, clientId: 'dograh-ui', scopes: 'openid organization' };
const ENDPOINTS = {
  authorizationEndpoint: `${ISSUER}/auth`,
  tokenEndpoint: `${ISSUER}/token`,
  endSessionEndpoint: `${ISSUER}/logout`,
};

function jwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'RS256' })}.${encode(payload)}.signature`;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('safeReturnTo', () => {
  it.each(['/workflow', '/workflow/12?tab=runs', '/'])('keeps the same-site path %s', (path) => {
    expect(safeReturnTo(path)).toBe(path);
  });

  it.each([
    'https://evil.example.test/',
    '//evil.example.test/',
    '/\\evil.example.test',
    'workflow',
    'javascript:alert(1)',
    '/ok\nSet-Cookie: x=1',
    '/api/auth/oidc/logout',
    '/auth/oidc-error?reason=state',
    '',
    null,
    undefined,
  ])('falls back to / for %j', (value) => {
    expect(safeReturnTo(value)).toBe('/');
  });

  it('is applied when building the login URL', () => {
    expect(loginUrl('//evil.example.test')).toBe('/api/auth/oidc/login?returnTo=%2F');
    expect(loginUrl('/workflow?x=1')).toBe('/api/auth/oidc/login?returnTo=%2Fworkflow%3Fx%3D1');
  });
});

describe('PKCE', () => {
  it('matches the RFC 7636 appendix B test vector', async () => {
    expect(await pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
  });

  it('generates distinct URL-safe tokens of the required length', () => {
    const verifier = randomToken(48);
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
    expect(randomToken()).not.toBe(randomToken());
  });
});

describe('token helpers', () => {
  it('reads claims and expiry without verifying', () => {
    const token = jwt({ exp: 1900000000, nonce: 'n-1', name: 'José' });
    expect(decodeJwtPayload(token)).toMatchObject({ nonce: 'n-1', name: 'José' });
    expect(tokenExpiresAt(token)).toBe(1900000000);
  });

  it.each(['', 'not-a-jwt', 'a.b', 'a.!!!.c', `a.${Buffer.from('[1]').toString('base64url')}.c`])(
    'returns null for the malformed token %j',
    (token) => {
      expect(decodeJwtPayload(token)).toBeNull();
      expect(tokenExpiresAt(token)).toBeNull();
    },
  );

  it('treats missing, expired and nearly expired tokens as expiring', () => {
    const now = 1_000_000;
    expect(isExpiring(undefined, now)).toBe(true);
    expect(isExpiring('garbage', now)).toBe(true);
    expect(isExpiring(jwt({ exp: now - 1 }), now)).toBe(true);
    expect(isExpiring(jwt({ exp: now + 10 }), now)).toBe(true);
    expect(isExpiring(jwt({ exp: now + 300 }), now)).toBe(false);
    expect(isExpiring(jwt({ sub: 'no-exp' }), now)).toBe(true);
  });
});

describe('URLs', () => {
  it('builds an authorization request with PKCE, state and nonce', () => {
    const url = new URL(
      buildAuthorizationUrl({
        config: CONFIG,
        endpoints: ENDPOINTS,
        redirectUri: 'https://app.example.test/api/auth/oidc/callback',
        state: 's-1',
        nonce: 'n-1',
        challenge: 'c-1',
      }),
    );
    expect(url.origin + url.pathname).toBe(`${ISSUER}/auth`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      response_type: 'code',
      client_id: 'dograh-ui',
      redirect_uri: 'https://app.example.test/api/auth/oidc/callback',
      scope: 'openid organization',
      state: 's-1',
      nonce: 'n-1',
      code_challenge: 'c-1',
      code_challenge_method: 'S256',
    });
  });

  it('builds a provider logout URL, or stays home without an end-session endpoint', () => {
    const url = new URL(
      buildLogoutUrl({
        config: CONFIG,
        endpoints: ENDPOINTS,
        idToken: 'id-token',
        postLogoutRedirectUri: 'https://app.example.test/',
      }),
    );
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: 'dograh-ui',
      post_logout_redirect_uri: 'https://app.example.test/',
      id_token_hint: 'id-token',
    });
    expect(
      buildLogoutUrl({
        config: CONFIG,
        endpoints: { ...ENDPOINTS, endSessionEndpoint: null },
        idToken: null,
        postLogoutRedirectUri: 'https://app.example.test/',
      }),
    ).toBe('https://app.example.test/');
  });

  it('derives the public origin from forwarded headers when present', () => {
    const direct = new NextRequest('http://10.0.0.5:3010/x', { headers: { host: '10.0.0.5:3010' } });
    expect(publicOrigin(direct)).toBe('http://10.0.0.5:3010');

    const proxied = new NextRequest('http://ui:3010/x', {
      headers: {
        host: 'ui:3010',
        'x-forwarded-proto': 'https, http',
        'x-forwarded-host': 'app.example.test',
      },
    });
    expect(publicOrigin(proxied)).toBe('https://app.example.test');
  });
});

describe('flow cookie', () => {
  it('accepts a complete flow and rejects anything else', () => {
    const flow = { state: 's', nonce: 'n', verifier: 'v', returnTo: '/' };
    expect(parseFlowCookie(JSON.stringify(flow))).toEqual(flow);
    expect(parseFlowCookie(undefined)).toBeNull();
    expect(parseFlowCookie('not json')).toBeNull();
    expect(parseFlowCookie(JSON.stringify({ ...flow, verifier: '' }))).toBeNull();
    expect(parseFlowCookie(JSON.stringify({ state: 's' }))).toBeNull();
  });
});

describe('provider requests', () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    clearOidcEndpointCache();
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('discovers endpoints once and caches them', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/auth`,
        token_endpoint: `${ISSUER}/token`,
        end_session_endpoint: `${ISSUER}/logout`,
      }),
    );

    expect(await getOidcEndpoints(ISSUER)).toEqual(ENDPOINTS);
    await getOidcEndpoints(ISSUER);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(`${ISSUER}/.well-known/openid-configuration`);
  });

  it('fetches discovery from the internal address but still requires the public issuer', async () => {
    vi.stubEnv('OIDC_INTERNAL_ISSUER_URL', 'http://keycloak:8080/realms/platform/');
    fetchMock.mockResolvedValue(
      jsonResponse({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/auth`,
        token_endpoint: 'http://keycloak:8080/realms/platform/token',
      }),
    );

    const endpoints = await getOidcEndpoints(ISSUER);

    expect(fetchMock.mock.calls[0][0]).toBe(
      'http://keycloak:8080/realms/platform/.well-known/openid-configuration',
    );
    expect(endpoints.tokenEndpoint).toBe('http://keycloak:8080/realms/platform/token');
    expect(endpoints.endSessionEndpoint).toBeNull();
  });

  it('refuses a discovery document for another issuer', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        issuer: 'https://evil.example.test',
        authorization_endpoint: 'https://evil.example.test/auth',
        token_endpoint: 'https://evil.example.test/token',
      }),
    );

    await expect(getOidcEndpoints(ISSUER)).rejects.toThrow('different issuer');
  });

  it('keeps the refresh token when the provider does not rotate it', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ access_token: 'new-access' }));

    const tokens = await refreshTokens({
      config: CONFIG,
      endpoints: ENDPOINTS,
      refreshToken: 'old-refresh',
    });

    expect(tokens).toEqual({ accessToken: 'new-access', refreshToken: 'old-refresh', idToken: null });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${ISSUER}/token`);
    expect(Object.fromEntries(init.body as URLSearchParams)).toEqual({
      client_id: 'dograh-ui',
      grant_type: 'refresh_token',
      refresh_token: 'old-refresh',
    });
  });

  it('fails when the provider refuses the refresh token', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ error: 'invalid_grant' }, 400));

    await expect(
      refreshTokens({ config: CONFIG, endpoints: ENDPOINTS, refreshToken: 'dead' }),
    ).rejects.toThrow('400');
  });
});
