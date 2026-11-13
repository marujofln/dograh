/**
 * OpenID Connect sign-in for `AUTH_PROVIDER=oidc`: authorization code flow
 * with PKCE, run by the Next server so tokens live in httpOnly cookies.
 *
 * Runs in both the Node and the Edge runtime (middleware refreshes expired
 * sessions), so it sticks to Web APIs: no `next/headers`, no Node crypto.
 */
import type { NextRequest } from 'next/server';

import { getServerBackendUrl } from '@/lib/apiClient';

import { OSS_TOKEN_COOKIE, OSS_USER_COOKIE, sessionCookieOptions } from './cookies';

export const OIDC_REFRESH_COOKIE = 'dograh_oidc_refresh';
export const OIDC_ID_TOKEN_COOKIE = 'dograh_oidc_id_token';
export const OIDC_FLOW_COOKIE = 'dograh_oidc_flow';
// Remembers which upstream identity provider this browser signs in with.
export const OIDC_IDP_COOKIE = 'dograh_oidc_idp';

// How long a sign-in may take between leaving for the provider and coming back.
const FLOW_MAX_AGE = 600;
// The cookies outlive the access token on purpose: the refresh token renews it,
// and the provider's own session lifetime is what actually ends the session.
const SESSION_MAX_AGE = 60 * 60 * 24 * 30;
// Renew a token this long before it expires, so a request made with it does
// not reach the API already expired.
export const EXPIRY_SKEW_SECONDS = 30;

export const OIDC_LOGIN_PATH = '/api/auth/oidc/login';
export const OIDC_CALLBACK_PATH = '/api/auth/oidc/callback';
export const OIDC_ERROR_PATH = '/auth/oidc-error';

export interface OidcConfig {
  issuer: string;
  clientId: string;
  scopes: string;
}

export interface OidcEndpoints {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  endSessionEndpoint: string | null;
}

export interface OidcTokens {
  accessToken: string;
  refreshToken: string | null;
  idToken: string | null;
}

export interface OidcSessionUser {
  id: string;
  email?: string;
  name?: string;
  organizationId?: string;
  provider: 'oidc';
}

export interface OidcFlowState {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
}

/** A cookie jar we can write to: `cookies()` or `NextResponse.cookies`. */
interface CookieWriter {
  set(name: string, value: string, options: Record<string, unknown>): unknown;
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

const endpointCache = new Map<string, OidcEndpoints>();

function trimSlashes(url: string): string {
  return url.replace(/\/+$/, '');
}

/**
 * Resolve the provider's endpoints from its discovery document.
 *
 * `OIDC_INTERNAL_ISSUER_URL` is for deployments where this server reaches the
 * provider at a different address than browsers do (e.g. a container network).
 * The document must still be for the configured issuer.
 */
export async function getOidcEndpoints(issuer: string): Promise<OidcEndpoints> {
  const cached = endpointCache.get(issuer);
  if (cached) {
    return cached;
  }

  const base = trimSlashes(process.env.OIDC_INTERNAL_ISSUER_URL || issuer);
  const response = await fetch(`${base}/.well-known/openid-configuration`, {
    cache: 'no-store',
  });
  if (!response.ok) {
    throw new Error(`OIDC discovery failed with status ${response.status}`);
  }
  const document = await response.json();
  if (document.issuer !== issuer) {
    throw new Error('OIDC discovery document is for a different issuer');
  }
  if (
    typeof document.authorization_endpoint !== 'string' ||
    typeof document.token_endpoint !== 'string'
  ) {
    throw new Error('OIDC discovery document is missing endpoints');
  }

  const endpoints: OidcEndpoints = {
    authorizationEndpoint: document.authorization_endpoint,
    tokenEndpoint: document.token_endpoint,
    endSessionEndpoint:
      typeof document.end_session_endpoint === 'string'
        ? document.end_session_endpoint
        : null,
  };
  endpointCache.set(issuer, endpoints);
  return endpoints;
}

/** Test hook: forget cached discovery documents. */
export function clearOidcEndpointCache(): void {
  endpointCache.clear();
}

// ---------------------------------------------------------------------------
// PKCE and request helpers
// ---------------------------------------------------------------------------

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function randomToken(byteLength = 32): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(verifier),
  );
  return base64Url(new Uint8Array(digest));
}

/**
 * Only same-site paths may be returned to after sign-in; anything else would
 * turn the login route into an open redirect.
 */
export function safeReturnTo(value: string | null | undefined): string {
  if (!value || !value.startsWith('/') || value.startsWith('//')) {
    return '/';
  }
  // Backslashes and control characters are how browsers get talked into
  // treating a "path" as another origin.
  if (/[\\\u0000-\u001f\u007f]/.test(value)) {
    return '/';
  }
  // Never bounce back into the sign-in machinery itself.
  if (value.startsWith('/api/auth/') || value.startsWith(OIDC_ERROR_PATH)) {
    return '/';
  }
  return value;
}

/**
 * The origin the browser used to reach this deployment. Behind a
 * TLS-terminating proxy the request Next sees is not the one the browser made,
 * so the forwarded headers win. The provider only redirects to registered
 * URIs, so a spoofed header cannot send the code anywhere else.
 */
export function publicOrigin(request: NextRequest): string {
  const first = (name: string) =>
    request.headers.get(name)?.split(',')[0]?.trim() || null;
  const proto = first('x-forwarded-proto') ?? request.nextUrl.protocol.replace(':', '');
  const host = first('x-forwarded-host') ?? request.headers.get('host') ?? request.nextUrl.host;
  return `${proto}://${host}`;
}

const IDP_HINT_MAX_AGE = 60 * 60 * 24 * 365;
const HINT_TOKEN = /^[A-Za-z0-9._-]{1,64}$/;
// Parameters this flow sets itself; the hint may never stand in for one.
const RESERVED_AUTHORIZATION_PARAMS = new Set([
  'response_type',
  'client_id',
  'redirect_uri',
  'scope',
  'state',
  'nonce',
  'code_challenge',
  'code_challenge_method',
]);

/**
 * Name of the authorization parameter that tells the provider which upstream
 * identity provider to use, from `OIDC_IDP_HINT_PARAM`. There is no standard
 * one: Keycloak calls it `kc_idp_hint`. Unset means the feature is off.
 */
export function idpHintParam(): string | null {
  const name = process.env.OIDC_IDP_HINT_PARAM?.trim();
  return name && HINT_TOKEN.test(name) && !RESERVED_AUTHORIZATION_PARAMS.has(name)
    ? name
    : null;
}

/** An identity provider alias safe to put in a URL and a cookie, or null. */
export function safeIdpHint(value: string | null | undefined): string | null {
  return value && HINT_TOKEN.test(value) ? value : null;
}

export function idpCookieOptions(request: NextRequest, maxAge = IDP_HINT_MAX_AGE) {
  return sessionCookieOptions(request, maxAge);
}

export function buildAuthorizationUrl(params: {
  config: OidcConfig;
  endpoints: OidcEndpoints;
  redirectUri: string;
  state: string;
  nonce: string;
  challenge: string;
  idpHint?: { param: string; value: string } | null;
}): string {
  const url = new URL(params.endpoints.authorizationEndpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', params.config.clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('scope', params.config.scopes);
  url.searchParams.set('state', params.state);
  url.searchParams.set('nonce', params.nonce);
  url.searchParams.set('code_challenge', params.challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (params.idpHint) {
    url.searchParams.set(params.idpHint.param, params.idpHint.value);
  }
  return url.toString();
}

export function buildLogoutUrl(params: {
  config: OidcConfig;
  endpoints: OidcEndpoints;
  idToken: string | null;
  postLogoutRedirectUri: string;
}): string {
  if (!params.endpoints.endSessionEndpoint) {
    return params.postLogoutRedirectUri;
  }
  const url = new URL(params.endpoints.endSessionEndpoint);
  url.searchParams.set('client_id', params.config.clientId);
  url.searchParams.set('post_logout_redirect_uri', params.postLogoutRedirectUri);
  if (params.idToken) {
    url.searchParams.set('id_token_hint', params.idToken);
  }
  return url.toString();
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

async function requestTokens(
  config: OidcConfig,
  endpoints: OidcEndpoints,
  form: Record<string, string>,
): Promise<OidcTokens> {
  const body = new URLSearchParams({ client_id: config.clientId, ...form });
  // Public clients rely on PKCE alone; a confidential client adds its secret.
  if (process.env.OIDC_CLIENT_SECRET) {
    body.set('client_secret', process.env.OIDC_CLIENT_SECRET);
  }
  const response = await fetch(endpoints.tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    cache: 'no-store',
  });
  if (!response.ok) {
    throw new Error(`OIDC token request failed with status ${response.status}`);
  }
  const data = await response.json();
  if (typeof data.access_token !== 'string' || !data.access_token) {
    throw new Error('OIDC token response has no access token');
  }
  return {
    accessToken: data.access_token,
    refreshToken: typeof data.refresh_token === 'string' ? data.refresh_token : null,
    idToken: typeof data.id_token === 'string' ? data.id_token : null,
  };
}

export function exchangeCode(params: {
  config: OidcConfig;
  endpoints: OidcEndpoints;
  code: string;
  verifier: string;
  redirectUri: string;
}): Promise<OidcTokens> {
  return requestTokens(params.config, params.endpoints, {
    grant_type: 'authorization_code',
    code: params.code,
    code_verifier: params.verifier,
    redirect_uri: params.redirectUri,
  });
}

export async function refreshTokens(params: {
  config: OidcConfig;
  endpoints: OidcEndpoints;
  refreshToken: string;
}): Promise<OidcTokens> {
  const tokens = await requestTokens(params.config, params.endpoints, {
    grant_type: 'refresh_token',
    refresh_token: params.refreshToken,
  });
  // Providers that do not rotate refresh tokens may omit it from the response.
  return { ...tokens, refreshToken: tokens.refreshToken ?? params.refreshToken };
}

/**
 * Read a JWT's claims WITHOUT verifying it. Only for tokens this server just
 * received from the provider over TLS, or to read an expiry: the API is what
 * verifies access tokens.
 */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return null;
  }
  try {
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
    const payload = JSON.parse(new TextDecoder().decode(bytes));
    return payload && typeof payload === 'object' && !Array.isArray(payload)
      ? payload
      : null;
  } catch {
    return null;
  }
}

/** Expiry of a token in seconds since the epoch, or null if it has none. */
export function tokenExpiresAt(token: string | null | undefined): number | null {
  if (!token) {
    return null;
  }
  const exp = decodeJwtPayload(token)?.exp;
  return typeof exp === 'number' && Number.isFinite(exp) ? exp : null;
}

/** True when the token is missing, unreadable, expired, or about to expire. */
export function isExpiring(
  token: string | null | undefined,
  nowSeconds = Date.now() / 1000,
): boolean {
  const expiresAt = tokenExpiresAt(token);
  return expiresAt === null || expiresAt - nowSeconds <= EXPIRY_SKEW_SECONDS;
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

export type BackendUserResult =
  | { ok: true; user: OidcSessionUser }
  | { ok: false; status: number };

/**
 * Ask the API who this access token is for. This is also what validates the
 * token: the API verifies signature, issuer, audience and organization.
 */
export async function fetchBackendUser(
  accessToken: string,
  idToken: string | null,
): Promise<BackendUserResult> {
  const response = await fetch(`${getServerBackendUrl()}/api/v1/auth/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    cache: 'no-store',
  });
  if (!response.ok) {
    return { ok: false, status: response.status };
  }
  const me = await response.json();
  const claims = (idToken && decodeJwtPayload(idToken)) || {};
  const pick = (value: unknown) =>
    typeof value === 'string' && value ? value : undefined;
  return {
    ok: true,
    user: {
      id: String(me.id),
      email: pick(me.email),
      name: pick(claims.name) ?? pick(claims.preferred_username) ?? pick(me.email),
      organizationId:
        me.organization_id === null || me.organization_id === undefined
          ? undefined
          : String(me.organization_id),
      provider: 'oidc',
    },
  };
}

/**
 * Each sign-in attempt gets its own cookie, named after its state. With a
 * single shared cookie, a second attempt started while the first is still at
 * the provider (another tab, or a background fetch that got redirected here)
 * would overwrite the first one's verifier and make its callback fail.
 */
export function flowCookieName(state: string): string | null {
  return /^[A-Za-z0-9_-]{20,128}$/.test(state) ? `${OIDC_FLOW_COOKIE}_${state}` : null;
}

/**
 * Whether the browser is navigating a page here, as opposed to a script
 * fetching in the background (router prefetches, data requests). Only a
 * navigation can be sent to the provider; a fetch cannot follow that redirect,
 * so starting a sign-in for it would only leave a stray flow cookie behind.
 * Clients that do not send Fetch Metadata are treated as navigations.
 */
export function isNavigation(request: NextRequest): boolean {
  const mode = request.headers.get('sec-fetch-mode');
  return mode === null || mode === 'navigate';
}

export function flowCookieOptions(request: NextRequest, maxAge = FLOW_MAX_AGE) {
  return { ...sessionCookieOptions(request, maxAge), path: '/api/auth/oidc' };
}

export function parseFlowCookie(value: string | undefined): OidcFlowState | null {
  if (!value) {
    return null;
  }
  try {
    const parsed = JSON.parse(value);
    const isString = (v: unknown) => typeof v === 'string' && v.length > 0;
    return isString(parsed.state) &&
      isString(parsed.nonce) &&
      isString(parsed.verifier) &&
      isString(parsed.returnTo)
      ? (parsed as OidcFlowState)
      : null;
  } catch {
    return null;
  }
}

export function writeSessionTokens(
  jar: CookieWriter,
  request: NextRequest,
  tokens: OidcTokens,
): void {
  const options = sessionCookieOptions(request, SESSION_MAX_AGE);
  jar.set(OSS_TOKEN_COOKIE, tokens.accessToken, options);
  if (tokens.refreshToken) {
    jar.set(OIDC_REFRESH_COOKIE, tokens.refreshToken, options);
  }
  if (tokens.idToken) {
    jar.set(OIDC_ID_TOKEN_COOKIE, tokens.idToken, options);
  }
}

export function writeSessionUser(
  jar: CookieWriter,
  request: NextRequest,
  user: OidcSessionUser,
): void {
  jar.set(
    OSS_USER_COOKIE,
    JSON.stringify(user),
    sessionCookieOptions(request, SESSION_MAX_AGE),
  );
}

/** Expire the session. `keepIdToken` leaves the logout hint for the error page. */
export function clearSession(
  jar: CookieWriter,
  request: NextRequest,
  { keepIdToken = false }: { keepIdToken?: boolean } = {},
): void {
  const options = sessionCookieOptions(request, 0);
  jar.set(OSS_TOKEN_COOKIE, '', options);
  jar.set(OSS_USER_COOKIE, '', options);
  jar.set(OIDC_REFRESH_COOKIE, '', options);
  if (!keepIdToken) {
    jar.set(OIDC_ID_TOKEN_COOKIE, '', options);
  }
}

export function loginUrl(returnTo: string): string {
  return `${OIDC_LOGIN_PATH}?returnTo=${encodeURIComponent(safeReturnTo(returnTo))}`;
}
