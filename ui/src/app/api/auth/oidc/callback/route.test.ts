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
import {
  clearOidcEndpointCache,
  OIDC_FLOW_COOKIE,
  OIDC_ID_TOKEN_COOKIE,
  OIDC_REFRESH_COOKIE,
} from '@/lib/auth/oidc';

import { GET } from './route';

const STATE = 'state-000000000000000000001';
const OTHER_STATE = 'state-000000000000000000002';
const FLOW = { state: STATE, nonce: 'nonce-1', verifier: 'verifier-1', returnTo: '/workflow/7' };
const flowCookie = (state: string) => `${OIDC_FLOW_COOKIE}_${state}`;

function jwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'RS256' })}.${encode(payload)}.signature`;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function callback(query: string, flow: unknown = FLOW, extraCookies = '') {
  const cookie = [
    flow
      ? `${flowCookie((flow as { state?: string }).state ?? STATE)}=${encodeURIComponent(JSON.stringify(flow))}`
      : '',
    extraCookies,
  ]
    .filter(Boolean)
    .join('; ');
  return new NextRequest(`https://app.example.test/api/auth/oidc/callback?${query}`, {
    headers: { host: 'app.example.test', cookie },
  });
}

describe('GET /api/auth/oidc/callback', () => {
  const fetchMock = vi.fn();
  let tokenResponse: Response;
  let meResponse: Response;

  beforeEach(() => {
    clearOidcEndpointCache();
    tokenResponse = json({
      access_token: 'access-1',
      refresh_token: 'refresh-1',
      id_token: jwt({ nonce: 'nonce-1', name: 'Ana Teste' }),
    });
    meResponse = json({ id: 7, email: 'ana@example.test', organization_id: 3 });
    fetchMock.mockReset();
    fetchMock.mockImplementation(async (url: string) => {
      if (url.endsWith('/.well-known/openid-configuration')) {
        return json({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/auth`,
          token_endpoint: `${ISSUER}/token`,
        });
      }
      if (url === `${ISSUER}/token`) return tokenResponse;
      if (url.endsWith('/api/v1/auth/me')) return meResponse;
      throw new Error(`unexpected fetch ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const calledToken = () => fetchMock.mock.calls.some(([url]) => url === `${ISSUER}/token`);

  it('stores the session and returns to where the user was going', async () => {
    const response = await GET(callback(`code=code-1&state=${STATE}`));

    expect(response.status).toBe(307);
    expect(response.headers.get('location')).toBe('https://app.example.test/workflow/7');
    expect(response.cookies.get(OSS_TOKEN_COOKIE)?.value).toBe('access-1');
    expect(response.cookies.get(OIDC_REFRESH_COOKIE)?.value).toBe('refresh-1');
    expect(response.cookies.get(OIDC_REFRESH_COOKIE)?.httpOnly).toBe(true);
    expect(response.cookies.get(OSS_TOKEN_COOKIE)?.secure).toBe(true);
    expect(JSON.parse(response.cookies.get(OSS_USER_COOKIE)!.value)).toEqual({
      id: '7',
      email: 'ana@example.test',
      name: 'Ana Teste',
      organizationId: '3',
      provider: 'oidc',
    });
    expect(response.cookies.get(flowCookie(STATE))?.value).toBe('');

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === `${ISSUER}/token`)!;
    expect(Object.fromEntries(tokenCall[1].body as URLSearchParams)).toEqual({
      client_id: 'dograh-ui',
      grant_type: 'authorization_code',
      code: 'code-1',
      code_verifier: 'verifier-1',
      redirect_uri: 'https://app.example.test/api/auth/oidc/callback',
    });
  });

  it.each([
    ['a state that is not ours', 'code=code-1&state=forged', FLOW],
    ['no state', 'code=code-1', FLOW],
    ['no flow cookie', `code=code-1&state=${STATE}`, null],
    ['a malformed flow cookie', `code=code-1&state=${STATE}`, { state: STATE }],
    ['a state that cannot name a cookie', 'code=code-1&state=a;b=c', FLOW],
  ])('refuses %s without spending the code', async (_name, query, flow) => {
    const response = await GET(callback(query, flow));

    expect(response.headers.get('location')).toBe(
      'https://app.example.test/auth/oidc-error?reason=state',
    );
    expect(calledToken()).toBe(false);
    expect(response.cookies.get(OSS_TOKEN_COOKIE)?.value).toBe('');
  });

  it('matches each response with its own attempt when two are in flight', async () => {
    const second = { ...FLOW, state: OTHER_STATE, verifier: 'verifier-2', returnTo: '/reports' };
    const cookies = `${flowCookie(OTHER_STATE)}=${encodeURIComponent(JSON.stringify(second))}`;

    const response = await GET(callback(`code=code-1&state=${STATE}`, FLOW, cookies));

    expect(response.headers.get('location')).toBe('https://app.example.test/workflow/7');
    const tokenCall = fetchMock.mock.calls.find(([url]) => url === `${ISSUER}/token`)!;
    expect((tokenCall[1].body as URLSearchParams).get('code_verifier')).toBe('verifier-1');
    // The other attempt is left alone to finish on its own.
    expect(response.cookies.get(flowCookie(OTHER_STATE))).toBeUndefined();
  });

  it('refuses an ID token minted for another sign-in request', async () => {
    tokenResponse = json({
      access_token: 'access-1',
      id_token: jwt({ nonce: 'someone-elses-nonce' }),
    });

    const response = await GET(callback(`code=code-1&state=${STATE}`));

    expect(response.headers.get('location')).toContain('reason=state');
    expect(response.cookies.get(OSS_TOKEN_COOKIE)?.value).toBe('');
  });

  it('refuses a token response without an ID token', async () => {
    tokenResponse = json({ access_token: 'access-1' });

    const response = await GET(callback(`code=code-1&state=${STATE}`));

    expect(response.headers.get('location')).toContain('reason=state');
  });

  it('explains when the API finds no single organization, keeping only the logout hint', async () => {
    meResponse = json({ detail: 'Token must carry exactly one organization' }, 403);

    const response = await GET(
      callback(`code=code-1&state=${STATE}`, FLOW, `${OSS_TOKEN_COOKIE}=old-session`),
    );

    expect(response.headers.get('location')).toBe(
      'https://app.example.test/auth/oidc-error?reason=organization',
    );
    expect(response.cookies.get(OSS_TOKEN_COOKIE)?.value).toBe('');
    expect(response.cookies.get(OIDC_REFRESH_COOKIE)?.value).toBe('');
    expect(response.cookies.get(OIDC_ID_TOKEN_COOKIE)?.value).toBeTruthy();
  });

  it('does not sign in when the API rejects the token', async () => {
    meResponse = json({ detail: 'Invalid or expired token' }, 401);

    const response = await GET(callback(`code=code-1&state=${STATE}`));

    expect(response.headers.get('location')).toContain('reason=rejected');
    expect(response.cookies.get(OSS_TOKEN_COOKIE)?.value).toBe('');
  });

  it('reports a provider error without exchanging anything', async () => {
    const response = await GET(callback(`error=access_denied&state=${STATE}`));

    expect(response.headers.get('location')).toContain('reason=provider');
    expect(calledToken()).toBe(false);
  });

  it('reports a failed code exchange', async () => {
    tokenResponse = json({ error: 'invalid_grant' }, 400);

    const response = await GET(callback(`code=replayed&state=${STATE}`));

    expect(response.headers.get('location')).toContain('reason=provider');
    expect(response.cookies.get(OSS_TOKEN_COOKIE)?.value).toBe('');
  });
});
