import type { CurrentUser } from '@stackframe/stack';

// Base user interface that all providers must support
export interface BaseUser {
  id: string;
  email?: string;
  name?: string;
  image?: string;
}

// Local/OSS user type
export interface LocalUser extends BaseUser {
  provider: 'local';
  organizationId?: string;
  displayName?: string;
  provider_id?: string;
}

// OpenID Connect user type: same shape as a local user, signed in elsewhere
export interface OidcUser extends BaseUser {
  provider: 'oidc';
  organizationId?: string;
  displayName?: string;
  provider_id?: string;
}

// Union type for all user types
export type AuthUser = CurrentUser | LocalUser | OidcUser;


export interface AuthToken {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
}

export interface TeamPermission {
  id: string;
}

export type AuthProvider = 'stack' | 'local' | 'oidc';

export interface AuthConfig {
  provider: AuthProvider;
  // Provider-specific configuration
  [key: string]: string | number | boolean;
}

