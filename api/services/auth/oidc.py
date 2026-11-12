"""OpenID Connect bearer-token verification (``AUTH_PROVIDER=oidc``).

Access tokens are verified locally: signature against the issuer's JWKS, then
``iss``, ``aud`` and expiry. Nothing is sent to the identity provider per
request; the JWKS is fetched once, cached, and refreshed on a schedule or when
a token names a signing key we have not seen (rate limited).

The organization comes from a claim the identity provider sets (for Keycloak,
the ``organization`` claim of its Organizations feature). A token must carry
exactly one organization: providers do issue valid tokens with none or with
several, and silently picking one would cross tenants.
"""

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import aiohttp
import jwt
from loguru import logger

# Signature algorithms a deployment may allow. Symmetric (HS*) algorithms and
# "none" are never accepted: the verification key is public, so accepting them
# would let anyone mint tokens.
ASYMMETRIC_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)

# Clock skew tolerated between this host and the identity provider.
LEEWAY_SECONDS = 30
# Cached keys are re-fetched after this long, so a key the provider retired
# stops being trusted.
KEY_TTL_SECONDS = 600
# Minimum gap between JWKS fetches triggered by an unknown key id. Without it,
# requests carrying made-up key ids would each cost a round trip to the provider.
MIN_REFRESH_INTERVAL_SECONDS = 30
FETCH_TIMEOUT_SECONDS = 5

# Keycloak stamps a ``typ`` claim on every token it issues. ID and refresh
# tokens must never be accepted as access tokens.
_NON_ACCESS_TOKEN_TYPES = frozenset({"ID", "Refresh", "Offline", "Logout"})


class OIDCConfigurationError(RuntimeError):
    """The OIDC settings are missing or unsafe."""


class OIDCTokenError(Exception):
    """The token is not a valid access token for this API."""


class OIDCOrganizationError(OIDCTokenError):
    """The token is valid but does not carry exactly one organization."""


class OIDCKeysUnavailableError(Exception):
    """The provider's signing keys could not be fetched and none are cached."""


@dataclass(frozen=True)
class OIDCIdentity:
    subject: str
    organization: str
    # Only set when the provider asserts the address is verified.
    email: str | None = None


def extract_organization(claims: dict[str, Any], claim_name: str) -> str:
    """Return the single organization named by ``claim_name``.

    Accepts the shapes providers emit: a string, a list of strings, or an
    object keyed by organization (Keycloak with organization ids enabled).
    """
    value = claims.get(claim_name)
    if isinstance(value, str):
        organizations = [value]
    elif isinstance(value, dict):
        organizations = list(value.keys())
    elif isinstance(value, list):
        organizations = value
    else:
        organizations = []

    if len(organizations) != 1:
        raise OIDCOrganizationError(
            f"expected exactly one organization, got {len(organizations)}"
        )
    organization = organizations[0]
    if not isinstance(organization, str) or not organization.strip():
        raise OIDCOrganizationError("organization is not a non-empty string")
    return organization


class OIDCVerifier:
    def __init__(
        self,
        *,
        issuer: str | None,
        audience: str | None,
        jwks_url: str | None = None,
        organization_claim: str = "organization",
        algorithms: list[str] | None = None,
    ):
        if not issuer:
            raise OIDCConfigurationError("OIDC_ISSUER must be set")
        if not audience:
            raise OIDCConfigurationError("OIDC_AUDIENCE must be set")
        if not organization_claim:
            raise OIDCConfigurationError("OIDC_ORGANIZATION_CLAIM must not be empty")
        algorithms = algorithms or ["RS256", "ES256"]
        unsafe = [a for a in algorithms if a not in ASYMMETRIC_ALGORITHMS]
        if unsafe:
            raise OIDCConfigurationError(
                "OIDC_ALLOWED_ALGORITHMS accepts only asymmetric algorithms; "
                f"rejected: {', '.join(unsafe)}"
            )

        self.issuer = issuer
        self.audience = audience
        self.organization_claim = organization_claim
        self.algorithms = list(algorithms)
        self._jwks_url = jwks_url or None

        self._keys: dict[str | None, Any] = {}
        self._fetched_at: float | None = None
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Signing keys
    # ------------------------------------------------------------------

    async def _fetch_json(self, url: str) -> dict[str, Any]:
        timeout = aiohttp.ClientTimeout(total=FETCH_TIMEOUT_SECONDS)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                response.raise_for_status()
                return await response.json(content_type=None)

    async def _resolve_jwks_url(self) -> str:
        if self._jwks_url:
            return self._jwks_url
        discovery = await self._fetch_json(
            self.issuer.rstrip("/") + "/.well-known/openid-configuration"
        )
        # OpenID Connect Discovery 1.0, section 4.3: the document must be for
        # the issuer we asked about.
        if discovery.get("issuer") != self.issuer:
            raise OIDCConfigurationError(
                "OIDC discovery document is for a different issuer"
            )
        jwks_url = discovery.get("jwks_uri")
        if not isinstance(jwks_url, str) or not jwks_url:
            raise OIDCConfigurationError("OIDC discovery document has no jwks_uri")
        self._jwks_url = jwks_url
        return jwks_url

    async def _refresh_keys(self) -> None:
        jwks = await self._fetch_json(await self._resolve_jwks_url())
        keys: dict[str | None, Any] = {}
        for entry in jwks.get("keys", []):
            if entry.get("use") not in (None, "sig"):
                continue
            try:
                key = jwt.PyJWK.from_dict(entry)
            except jwt.PyJWTError:
                # A key type this build cannot use; other keys may still work.
                continue
            keys[key.key_id] = key
        if not keys:
            raise OIDCKeysUnavailableError("the JWKS holds no usable signing key")
        self._keys = keys
        self._fetched_at = time.monotonic()

    def _lookup(self, key_id: str | None) -> Any | None:
        if key_id is None:
            # Providers with a single key may omit ``kid``.
            return next(iter(self._keys.values())) if len(self._keys) == 1 else None
        return self._keys.get(key_id)

    async def _signing_key(self, key_id: str | None) -> Any:
        async with self._lock:
            now = time.monotonic()
            age = None if self._fetched_at is None else now - self._fetched_at
            key = self._lookup(key_id)

            expired = age is None or age >= KEY_TTL_SECONDS
            unknown = key is None and (
                age is None or age >= MIN_REFRESH_INTERVAL_SECONDS
            )
            if expired or unknown:
                try:
                    await self._refresh_keys()
                except OIDCConfigurationError:
                    raise
                except Exception as exc:
                    if not self._keys:
                        raise OIDCKeysUnavailableError(
                            "could not fetch the provider's signing keys"
                        ) from exc
                    # Keep serving with the cached keys, and wait before retrying.
                    logger.warning(
                        f"OIDC JWKS refresh failed; using cached keys: {exc}"
                    )
                    self._fetched_at = now
                key = self._lookup(key_id)

            if key is None:
                raise OIDCTokenError("token is signed with an unknown key")
            return key

    # ------------------------------------------------------------------
    # Tokens
    # ------------------------------------------------------------------

    async def verify(self, authorization: str | None) -> OIDCIdentity:
        """Verify an ``Authorization`` header value and return who it is for."""
        if not authorization:
            raise OIDCTokenError("missing token")
        token = (authorization.removeprefix("Bearer ")).strip()
        if not token:
            raise OIDCTokenError("missing token")

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise OIDCTokenError("malformed token") from exc
        if header.get("alg") not in self.algorithms:
            raise OIDCTokenError("token algorithm is not allowed")

        key = await self._signing_key(header.get("kid"))

        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=self.algorithms,
                issuer=self.issuer,
                audience=self.audience,
                leeway=LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except (jwt.PyJWTError, ValueError, TypeError) as exc:
            raise OIDCTokenError(f"token rejected: {type(exc).__name__}") from exc

        if claims.get("typ") in _NON_ACCESS_TOKEN_TYPES:
            raise OIDCTokenError("not an access token")

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise OIDCTokenError("token has no subject")

        organization = extract_organization(claims, self.organization_claim)

        email = claims.get("email")
        verified = claims.get("email_verified") is True
        return OIDCIdentity(
            subject=subject,
            organization=organization,
            email=email if verified and isinstance(email, str) and email else None,
        )


_verifier: OIDCVerifier | None = None


def get_oidc_verifier() -> OIDCVerifier:
    """Return the process-wide verifier, built from the environment.

    Raises ``OIDCConfigurationError`` when the settings are missing or unsafe;
    the app calls this at startup so a misconfigured deployment fails to boot
    instead of rejecting every request.
    """
    global _verifier
    if _verifier is None:
        from api.constants import (
            OIDC_ALLOWED_ALGORITHMS,
            OIDC_AUDIENCE,
            OIDC_ISSUER,
            OIDC_JWKS_URL,
            OIDC_ORGANIZATION_CLAIM,
        )

        _verifier = OIDCVerifier(
            issuer=OIDC_ISSUER,
            audience=OIDC_AUDIENCE,
            jwks_url=OIDC_JWKS_URL,
            organization_claim=OIDC_ORGANIZATION_CLAIM,
            algorithms=OIDC_ALLOWED_ALGORITHMS,
        )
    return _verifier
