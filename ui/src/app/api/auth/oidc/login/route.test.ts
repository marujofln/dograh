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

import { clearOidcEndpointCache, OIDC_FLOW_COOKIE, pkceChallenge } from '@/lib/auth/oidc';

import { GET } from './route';

function login(query = '', headers: Record<string, string> = {}) {
  return new NextRequest(`https://app.example.test/api/auth/oidc/login${query}`, {
    headers: { host: 'app.example.test', ...headers },
  });
}

describe('GET /api/auth/oidc/login', () => {
  beforeEach(() => {
    clearOidcEndpointCache();
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            issuer: ISSUER,
            authorization_endpoint: `${ISSUER}/auth`,
            token_endpoint: `${ISSUER}/token`,
          }),
        ),
      ),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends a navigation to the provider and remembers the attempt under its state', async () => {
    const response = await GET(login('?returnTo=/workflow/7', { 'sec-fetch-mode': 'navigate' }));

    expect(response.status).toBe(307);
    const target = new URL(response.headers.get('location')!);
    expect(target.origin + target.pathname).toBe(`${ISSUER}/auth`);
    const state = target.searchParams.get('state')!;

    const cookie = response.cookies.get(`${OIDC_FLOW_COOKIE}_${state}`)!;
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.path).toBe('/api/auth/oidc');
    const flow = JSON.parse(cookie.value);
    expect(flow).toMatchObject({ state, returnTo: '/workflow/7' });
    expect(target.searchParams.get('nonce')).toBe(flow.nonce);
    // The verifier stays in the cookie; only its challenge goes to the provider.
    expect(target.searchParams.get('code_challenge')).toBe(await pkceChallenge(flow.verifier));
    expect(response.headers.get('location')).not.toContain(flow.verifier);
  });

  it('gives every attempt its own state and cookie', async () => {
    const first = await GET(login());
    const second = await GET(login());

    const name = (r: Response) =>
      `${OIDC_FLOW_COOKIE}_${new URL(r.headers.get('location')!).searchParams.get('state')}`;
    expect(name(first)).not.toBe(name(second));
  });

  it.each(['cors', 'same-origin', 'no-cors'])(
    'does not start a sign-in for a background %s fetch',
    async (mode) => {
      const response = await GET(login('', { 'sec-fetch-mode': mode }));

      expect(response.status).toBe(401);
      expect(response.headers.get('set-cookie')).toBeNull();
    },
  );

  it('never returns to another site', async () => {
    const response = await GET(login('?returnTo=https://evil.example.test/'));

    const state = new URL(response.headers.get('location')!).searchParams.get('state');
    const flow = JSON.parse(response.cookies.get(`${OIDC_FLOW_COOKIE}_${state}`)!.value);
    expect(flow.returnTo).toBe('/');
  });
});
