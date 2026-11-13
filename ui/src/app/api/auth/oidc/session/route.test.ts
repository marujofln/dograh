// @vitest-environment node
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const ISSUER = 'https://idp.example.test/realms/platform';

vi.mock('@/lib/auth/config', () => ({
  getOidcConfig: vi.fn(async () => ({
    issuer: ISSUER,
    clientId: 'dograh-ui',
    scopes: 'openid organization',
  })),
}));

import { OSS_TOKEN_COOKIE, OSS_USER_COOKIE } from '@/lib/auth/cookies';
import { clearOidcEndpointCache, OIDC_REFRESH_COOKIE } from '@/lib/auth/oidc';

import { GET } from './route';

function jwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'RS256' })}.${encode(payload)}.signature`;
}

const future = () => Math.floor(Date.now() / 1000) + 300;
const past = () => Math.floor(Date.now() / 1000) - 300;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function session(cookies: Record<string, string>) {
  return new NextRequest('https://app.example.test/api/auth/oidc/session', {
    headers: {
      cookie: Object.entries(cookies)
        .map(([name, value]) => `${name}=${value}`)
        .join('; '),
    },
  });
}

describe('GET /api/auth/oidc/session', () => {
  const fetchMock = vi.fn();
  // Access tokens the fake API accepts.
  let accepted: Set<string>;
  let renewedToken: string;
  let tokenStatus: number;
  let apiStatus: number | null;

  beforeEach(() => {
    clearOidcEndpointCache();
    accepted = new Set();
    renewedToken = jwt({ exp: future(), jti: 'renewed' });
    tokenStatus = 200;
    apiStatus = null;
    fetchMock.mockReset();
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/.well-known/openid-configuration')) {
        return json({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/auth`,
          token_endpoint: `${ISSUER}/token`,
        });
      }
      if (url === `${ISSUER}/token`) {
        return tokenStatus === 200
          ? json({ access_token: renewedToken })
          : json({ error: 'invalid_grant' }, tokenStatus);
      }
      if (url.endsWith('/api/v1/auth/me')) {
        if (apiStatus) return json({ detail: 'x' }, apiStatus);
        const token = String(new Headers(init?.headers).get('authorization')).replace('Bearer ', '');
        return accepted.has(token)
          ? json({ id: 7, email: 'ana@example.test', organization_id: 3 })
          : json({ detail: 'Invalid or expired token' }, 401);
      }
      throw new Error(`unexpected fetch ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const tokenCalls = () => fetchMock.mock.calls.filter(([url]) => url === `${ISSUER}/token`).length;

  it('hands out a token the API accepts, without touching the provider', async () => {
    const access = jwt({ exp: future() });
    accepted.add(access);

    const response = await GET(session({ [OSS_TOKEN_COOKIE]: access }));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.token).toBe(access);
    expect(body.user).toMatchObject({ id: '7', organizationId: '3', provider: 'oidc' });
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(tokenCalls()).toBe(0);
  });

  it('renews an expired token with the refresh token', async () => {
    accepted.add(renewedToken);

    const response = await GET(
      session({ [OSS_TOKEN_COOKIE]: jwt({ exp: past() }), [OIDC_REFRESH_COOKIE]: 'refresh-1' }),
    );

    expect(response.status).toBe(200);
    expect((await response.json()).token).toBe(renewedToken);
    expect(response.cookies.get(OSS_TOKEN_COOKIE)?.value).toBe(renewedToken);
    expect(response.cookies.get(OIDC_REFRESH_COOKIE)?.value).toBe('refresh-1');
  });

  it('does not treat an unexpired token from elsewhere as a session', async () => {
    // e.g. the cookie of another deployment on the same host: cookies ignore ports.
    const foreign = jwt({ exp: future(), iss: 'another-deployment' });

    const response = await GET(
      session({ [OSS_TOKEN_COOKIE]: foreign, [OSS_USER_COOKIE]: '{"id":"1","name":"Someone"}' }),
    );

    expect(response.status).toBe(401);
    expect(response.cookies.get(OSS_TOKEN_COOKIE)?.value).toBe('');
    expect(response.cookies.get(OSS_USER_COOKIE)?.value).toBe('');
  });

  it('replaces a rejected token when the provider session is still good', async () => {
    accepted.add(renewedToken);

    const response = await GET(
      session({ [OSS_TOKEN_COOKIE]: jwt({ exp: future() }), [OIDC_REFRESH_COOKIE]: 'refresh-1' }),
    );

    expect(response.status).toBe(200);
    expect((await response.json()).token).toBe(renewedToken);
    expect(tokenCalls()).toBe(1);
  });

  it.each([
    ['there are no cookies', {}],
    ['the token expired and there is no refresh token', { [OSS_TOKEN_COOKIE]: jwt({ exp: past() }) }],
  ])('is unauthenticated when %s', async (_name, cookies) => {
    const response = await GET(session(cookies));

    expect(response.status).toBe(401);
  });

  it('is unauthenticated when the provider refuses the refresh token', async () => {
    tokenStatus = 400;

    const response = await GET(
      session({ [OSS_TOKEN_COOKIE]: jwt({ exp: past() }), [OIDC_REFRESH_COOKIE]: 'dead' }),
    );

    expect(response.status).toBe(401);
    expect(response.cookies.get(OIDC_REFRESH_COOKIE)?.value).toBe('');
  });

  it('is unauthenticated when the user no longer has a single organization', async () => {
    apiStatus = 403;

    const response = await GET(session({ [OSS_TOKEN_COOKIE]: jwt({ exp: future() }) }));

    expect(response.status).toBe(401);
  });

  it('keeps the session when the API is down', async () => {
    apiStatus = 502;
    const access = jwt({ exp: future() });

    const response = await GET(session({ [OSS_TOKEN_COOKIE]: access }));

    expect(response.status).toBe(503);
    expect(response.cookies.get(OSS_TOKEN_COOKIE)).toBeUndefined();
  });
});
