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

import {
  clearOidcEndpointCache,
  OIDC_FLOW_COOKIE,
  OIDC_IDP_COOKIE,
  pkceChallenge,
} from '@/lib/auth/oidc';

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
    vi.unstubAllEnvs();
  });

  const hintIn = (response: Response, param = 'kc_idp_hint') =>
    new URL(response.headers.get('location')!).searchParams.get(param);

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

  describe('identity provider hint', () => {
    beforeEach(() => {
      vi.stubEnv('OIDC_IDP_HINT_PARAM', 'kc_idp_hint');
    });

    it('passes ?idp= to the provider and remembers it', async () => {
      const response = await GET(login('?idp=acme-sso&returnTo=/reports'));

      expect(hintIn(response)).toBe('acme-sso');
      const cookie = response.cookies.get(OIDC_IDP_COOKIE)!;
      expect(cookie.value).toBe('acme-sso');
      expect(cookie.httpOnly).toBe(true);
      expect(cookie.maxAge).toBeGreaterThan(60 * 60 * 24 * 30);
    });

    it('goes back to the remembered provider when none is asked for', async () => {
      const response = await GET(login('', { cookie: `${OIDC_IDP_COOKIE}=acme-sso` }));

      expect(hintIn(response)).toBe('acme-sso');
      expect(response.cookies.get(OIDC_IDP_COOKIE)).toBeUndefined();
    });

    it('lets the address override what was remembered', async () => {
      const response = await GET(
        login('?idp=globex-sso', { cookie: `${OIDC_IDP_COOKIE}=acme-sso` }),
      );

      expect(hintIn(response)).toBe('globex-sso');
      expect(response.cookies.get(OIDC_IDP_COOKIE)?.value).toBe('globex-sso');
    });

    it('forgets the provider on an empty ?idp=', async () => {
      const response = await GET(login('?idp=', { cookie: `${OIDC_IDP_COOKIE}=acme-sso` }));

      expect(hintIn(response)).toBeNull();
      expect(response.cookies.get(OIDC_IDP_COOKIE)?.value).toBe('');
    });

    it.each(['a b', 'a&state=x', '../x', 'a'.repeat(65), 'ação'])(
      'ignores the malformed alias %j',
      async (alias) => {
        const response = await GET(login(`?idp=${encodeURIComponent(alias)}`));

        expect(hintIn(response)).toBeNull();
        // The flow's own parameters are untouched.
        const target = new URL(response.headers.get('location')!);
        expect(target.searchParams.getAll('state')).toHaveLength(1);
        expect(response.cookies.get(OIDC_IDP_COOKIE)?.value || '').toBe('');
      },
    );

    it('ignores a tampered cookie', async () => {
      const response = await GET(login('', { cookie: `${OIDC_IDP_COOKIE}=a%26scope%3Dx` }));

      expect(hintIn(response)).toBeNull();
    });

    it.each(['state', 'redirect_uri', 'scope', 'bad name', ''])(
      'is off when OIDC_IDP_HINT_PARAM is %j',
      async (name) => {
        vi.stubEnv('OIDC_IDP_HINT_PARAM', name);

        const response = await GET(login('?idp=acme-sso'));

        const target = new URL(response.headers.get('location')!);
        expect([...target.searchParams.values()]).not.toContain('acme-sso');
        expect(target.searchParams.get('scope')).toBe('openid organization');
        expect(response.cookies.get(OIDC_IDP_COOKIE)).toBeUndefined();
      },
    );
  });

  it('ignores ?idp= when no hint parameter is configured', async () => {
    const response = await GET(login('?idp=acme-sso'));

    expect(response.headers.get('location')).not.toContain('acme-sso');
    expect(response.cookies.get(OIDC_IDP_COOKIE)).toBeUndefined();
  });

  it('never returns to another site', async () => {
    const response = await GET(login('?returnTo=https://evil.example.test/'));

    const state = new URL(response.headers.get('location')!).searchParams.get('state');
    const flow = JSON.parse(response.cookies.get(`${OIDC_FLOW_COOKIE}_${state}`)!.value);
    expect(flow.returnTo).toBe('/');
  });
});
