'use client';

import React, { useEffect, useMemo, useRef, useState } from 'react';

import logger from '@/lib/logger';

import type { AuthUser, OidcUser } from '../types';
import { AuthContext } from './AuthProvider';

// Ask the server for a fresh token this long before the current one expires.
const RENEW_BEFORE_EXPIRY_SECONDS = 30;
const SESSION_URL = '/api/auth/oidc/session';
const ERROR_PATH = '/auth/oidc-error';

interface Session {
  token: string;
  user: OidcUser;
  expiresAt: number | null;
}

function loginUrl(): string {
  const { pathname, search } = window.location;
  return `/api/auth/oidc/login?returnTo=${encodeURIComponent(pathname + search)}`;
}

export function OidcProviderWrapper({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<OidcUser | null>(null);
  const [loading, setLoading] = useState(true);
  const sessionRef = useRef<Session | null>(null);
  // Many components ask for the token at once; they share one renewal.
  const pendingRef = useRef<Promise<Session | null> | null>(null);

  const redirectToLogin = React.useCallback(() => {
    // The error page is where failed sign-ins land; leaving it automatically
    // would loop straight back to the provider.
    if (!window.location.pathname.startsWith(ERROR_PATH)) {
      window.location.href = loginUrl();
    }
  }, []);

  const loadSession = React.useCallback((): Promise<Session | null> => {
    if (!pendingRef.current) {
      pendingRef.current = (async () => {
        try {
          const response = await fetch(SESSION_URL, { cache: 'no-store' });
          if (response.ok) {
            const session = (await response.json()) as Session;
            sessionRef.current = session;
            return session;
          }
          if (response.status !== 401) {
            logger.error('Failed to load OIDC session', response.status);
            // Keep what we have: a transient server error is not a sign-out.
            return sessionRef.current;
          }
        } catch (error) {
          logger.error('Error loading OIDC session', error);
          return sessionRef.current;
        }
        sessionRef.current = null;
        return null;
      })().finally(() => {
        pendingRef.current = null;
      });
    }
    return pendingRef.current;
  }, []);

  useEffect(() => {
    let cancelled = false;
    loadSession().then((session) => {
      if (cancelled) return;
      if (session) {
        setUser(session.user);
      } else {
        redirectToLogin();
      }
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, [loadSession, redirectToLogin]);

  const getAccessToken = React.useCallback(async () => {
    if (typeof window === 'undefined') {
      return 'ssr-placeholder-token';
    }
    const current = sessionRef.current;
    const fresh =
      current &&
      (current.expiresAt === null ||
        current.expiresAt - Date.now() / 1000 > RENEW_BEFORE_EXPIRY_SECONDS);
    if (fresh) {
      return current.token;
    }
    const session = await loadSession();
    if (!session) {
      setUser(null);
      redirectToLogin();
      return '';
    }
    return session.token;
  }, [loadSession, redirectToLogin]);

  const logout = React.useCallback(async () => {
    let target = '/';
    try {
      const response = await fetch('/api/auth/oidc/logout', { method: 'POST' });
      if (response.ok) {
        target = (await response.json()).logoutUrl || target;
      }
    } catch (error) {
      logger.error('Error during logout', error);
    }
    setUser(null);
    sessionRef.current = null;
    window.location.href = target;
  }, []);

  const contextValue = useMemo(() => ({
    user: user as AuthUser,
    isAuthenticated: !!user,
    loading,
    getAccessToken,
    redirectToLogin,
    logout,
    provider: 'oidc' as const,
  }), [user, loading, getAccessToken, redirectToLogin, logout]);

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}
