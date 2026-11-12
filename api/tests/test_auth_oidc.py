import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from api.services.auth import depends as auth_depends
from api.services.auth import oidc
from api.services.auth.oidc import (
    OIDCConfigurationError,
    OIDCIdentity,
    OIDCKeysUnavailableError,
    OIDCOrganizationError,
    OIDCTokenError,
    OIDCVerifier,
    extract_organization,
)

ISSUER = "https://idp.example.test/realms/platform"
AUDIENCE = "dograh-api"
JWKS_URL = "https://idp.example.test/jwks"


class _Key:
    def __init__(self, key_id: str):
        self.key_id = key_id
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk(self) -> dict:
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(
            self.private.public_key(), as_dict=True
        )
        return {**jwk, "kid": self.key_id, "use": "sig", "alg": "RS256"}

    def public_pem(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


@pytest.fixture(scope="module")
def key() -> _Key:
    return _Key("key-1")


@pytest.fixture(scope="module")
def other_key() -> _Key:
    return _Key("key-2")


def _claims(**overrides) -> dict:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": [AUDIENCE, "account"],
        "sub": "user-1",
        "iat": now,
        "exp": now + 300,
        "typ": "Bearer",
        "organization": ["acme"],
        "email": "Ana@Example.test",
        "email_verified": True,
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def _token(key: _Key, claims: dict | None = None, **header) -> str:
    return jwt.encode(
        claims if claims is not None else _claims(),
        key.private,
        algorithm="RS256",
        headers={"kid": key.key_id, **header},
    )


class _Fetcher:
    """Stands in for the HTTP fetch and records what was requested."""

    def __init__(self, documents: dict):
        self.documents = documents
        self.calls: list[str] = []
        self.fail = False

    async def __call__(self, url: str) -> dict:
        self.calls.append(url)
        if self.fail:
            raise RuntimeError("provider unreachable")
        return self.documents[url]


def _verifier(monkeypatch, *keys: _Key, **kwargs) -> tuple[OIDCVerifier, _Fetcher]:
    fetcher = _Fetcher({JWKS_URL: {"keys": [k.jwk() for k in keys]}})
    verifier = OIDCVerifier(
        issuer=ISSUER, audience=AUDIENCE, jwks_url=JWKS_URL, **kwargs
    )
    monkeypatch.setattr(verifier, "_fetch_json", fetcher)
    return verifier, fetcher


# ----------------------------------------------------------------------
# Token verification
# ----------------------------------------------------------------------


async def test_valid_token_yields_identity(monkeypatch, key):
    verifier, fetcher = _verifier(monkeypatch, key)

    identity = await verifier.verify(f"Bearer {_token(key)}")

    assert identity == OIDCIdentity(
        subject="user-1", organization="acme", email="Ana@Example.test"
    )
    assert fetcher.calls == [JWKS_URL]


async def test_keys_are_cached_between_requests(monkeypatch, key):
    verifier, fetcher = _verifier(monkeypatch, key)

    await verifier.verify(_token(key))
    await verifier.verify(_token(key))

    assert len(fetcher.calls) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": int(time.time()) - 3600},
        {"aud": "another-api"},
        {"aud": None},
        {"iss": "https://evil.example.test/realms/platform"},
        {"sub": None},
        {"exp": None},
        {"iat": None},
        {"nbf": int(time.time()) + 3600},
        {"typ": "ID"},
        {"typ": "Refresh"},
    ],
    ids=[
        "expired",
        "wrong-audience",
        "no-audience",
        "wrong-issuer",
        "no-subject",
        "no-expiry",
        "no-issued-at",
        "not-yet-valid",
        "id-token",
        "refresh-token",
    ],
)
async def test_invalid_claims_are_rejected(monkeypatch, key, overrides):
    verifier, _ = _verifier(monkeypatch, key)

    with pytest.raises(OIDCTokenError):
        await verifier.verify(_token(key, _claims(**overrides)))


async def test_token_signed_by_another_key_with_known_kid_is_rejected(
    monkeypatch, key, other_key
):
    verifier, _ = _verifier(monkeypatch, key)
    forged = _token(other_key, kid=key.key_id)

    with pytest.raises(OIDCTokenError):
        await verifier.verify(forged)


async def test_unsigned_token_is_rejected(monkeypatch, key):
    verifier, fetcher = _verifier(monkeypatch, key)
    unsigned = jwt.encode(_claims(), key=None, algorithm="none")

    with pytest.raises(OIDCTokenError, match="algorithm"):
        await verifier.verify(unsigned)
    # Rejected on the header alone, before any key is fetched.
    assert fetcher.calls == []


async def test_hmac_token_keyed_with_the_public_key_is_rejected(monkeypatch, key):
    """The classic algorithm-confusion attack: the public key is not a secret."""
    verifier, _ = _verifier(monkeypatch, key)
    # PyJWT refuses to *sign* HS256 with a PEM key, so build the forgery by hand.
    import base64
    import hashlib
    import hmac
    import json

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    signing_input = (
        b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": key.key_id}).encode())
        + "."
        + b64(json.dumps(_claims(organization=["victim"])).encode())
    )
    signature = hmac.new(
        key.public_pem(), signing_input.encode(), hashlib.sha256
    ).digest()
    forged = f"{signing_input}.{b64(signature)}"

    with pytest.raises(OIDCTokenError, match="algorithm"):
        await verifier.verify(forged)


@pytest.mark.parametrize("value", ["", "Bearer ", "not-a-jwt", "Bearer a.b.c"])
async def test_malformed_tokens_are_rejected(monkeypatch, key, value):
    verifier, _ = _verifier(monkeypatch, key)

    with pytest.raises(OIDCTokenError):
        await verifier.verify(value)


async def test_unverified_email_is_not_trusted(monkeypatch, key):
    verifier, _ = _verifier(monkeypatch, key)

    identity = await verifier.verify(_token(key, _claims(email_verified=False)))

    assert identity.email is None


# ----------------------------------------------------------------------
# Organization claim
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["acme", ["acme"], {"acme": {"id": "0f4c"}}],
    ids=["string", "list", "object"],
)
def test_single_organization_is_extracted_from_every_shape(value):
    assert extract_organization({"organization": value}, "organization") == "acme"


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {},
        "",
        "  ",
        ["acme", "globex"],
        {"acme": {}, "globex": {}},
        [42],
        [None],
        42,
        True,
    ],
)
def test_zero_or_many_organizations_are_rejected(value):
    with pytest.raises(OIDCOrganizationError):
        extract_organization({"organization": value}, "organization")


async def test_token_with_two_organizations_is_rejected(monkeypatch, key):
    verifier, _ = _verifier(monkeypatch, key)

    with pytest.raises(OIDCOrganizationError):
        await verifier.verify(_token(key, _claims(organization=["acme", "globex"])))


async def test_token_without_organization_is_rejected(monkeypatch, key):
    verifier, _ = _verifier(monkeypatch, key)

    with pytest.raises(OIDCOrganizationError):
        await verifier.verify(_token(key, _claims(organization=None)))


async def test_organization_claim_name_is_configurable(monkeypatch, key):
    verifier, _ = _verifier(monkeypatch, key, organization_claim="tenant")

    identity = await verifier.verify(
        _token(key, _claims(organization=["ignored"], tenant="globex"))
    )

    assert identity.organization == "globex"


# ----------------------------------------------------------------------
# Signing keys
# ----------------------------------------------------------------------


async def test_rotated_key_is_picked_up(monkeypatch, key, other_key):
    verifier, fetcher = _verifier(monkeypatch, key)
    await verifier.verify(_token(key))

    fetcher.documents[JWKS_URL] = {"keys": [other_key.jwk()]}
    monkeypatch.setattr(oidc, "MIN_REFRESH_INTERVAL_SECONDS", 0)

    identity = await verifier.verify(_token(other_key))

    assert identity.subject == "user-1"
    assert len(fetcher.calls) == 2


async def test_unknown_key_ids_do_not_cause_a_fetch_per_request(
    monkeypatch, key, other_key
):
    verifier, fetcher = _verifier(monkeypatch, key)
    await verifier.verify(_token(key))

    for _ in range(5):
        with pytest.raises(OIDCTokenError, match="unknown key"):
            await verifier.verify(_token(other_key))

    assert len(fetcher.calls) == 1


async def test_retired_key_stops_being_trusted_after_ttl(monkeypatch, key, other_key):
    verifier, fetcher = _verifier(monkeypatch, key)
    await verifier.verify(_token(key))

    fetcher.documents[JWKS_URL] = {"keys": [other_key.jwk()]}
    monkeypatch.setattr(oidc, "KEY_TTL_SECONDS", 0)

    with pytest.raises(OIDCTokenError):
        await verifier.verify(_token(key))


async def test_cached_keys_survive_a_failed_refresh(monkeypatch, key):
    verifier, fetcher = _verifier(monkeypatch, key)
    await verifier.verify(_token(key))

    fetcher.fail = True
    monkeypatch.setattr(oidc, "KEY_TTL_SECONDS", 0)

    identity = await verifier.verify(_token(key))

    assert identity.subject == "user-1"


async def test_no_keys_and_unreachable_provider_is_unavailable(monkeypatch, key):
    verifier, fetcher = _verifier(monkeypatch, key)
    fetcher.fail = True

    with pytest.raises(OIDCKeysUnavailableError):
        await verifier.verify(_token(key))


async def test_encryption_only_keys_are_ignored(monkeypatch, key):
    verifier, fetcher = _verifier(monkeypatch, key)
    fetcher.documents[JWKS_URL] = {"keys": [{**key.jwk(), "use": "enc"}]}

    with pytest.raises(OIDCKeysUnavailableError):
        await verifier.verify(_token(key))


async def test_jwks_url_comes_from_discovery(monkeypatch, key):
    verifier = OIDCVerifier(issuer=ISSUER, audience=AUDIENCE)
    fetcher = _Fetcher(
        {
            f"{ISSUER}/.well-known/openid-configuration": {
                "issuer": ISSUER,
                "jwks_uri": JWKS_URL,
            },
            JWKS_URL: {"keys": [key.jwk()]},
        }
    )
    monkeypatch.setattr(verifier, "_fetch_json", fetcher)

    await verifier.verify(_token(key))

    assert fetcher.calls == [f"{ISSUER}/.well-known/openid-configuration", JWKS_URL]


async def test_discovery_for_another_issuer_is_refused(monkeypatch, key):
    verifier = OIDCVerifier(issuer=ISSUER, audience=AUDIENCE)
    fetcher = _Fetcher(
        {
            f"{ISSUER}/.well-known/openid-configuration": {
                "issuer": "https://evil.example.test",
                "jwks_uri": JWKS_URL,
            },
            JWKS_URL: {"keys": [key.jwk()]},
        }
    )
    monkeypatch.setattr(verifier, "_fetch_json", fetcher)

    with pytest.raises(OIDCConfigurationError):
        await verifier.verify(_token(key))
    assert JWKS_URL not in fetcher.calls


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"issuer": None, "audience": AUDIENCE},
        {"issuer": ISSUER, "audience": None},
        {"issuer": ISSUER, "audience": AUDIENCE, "algorithms": ["HS256"]},
        {"issuer": ISSUER, "audience": AUDIENCE, "algorithms": ["RS256", "none"]},
        {"issuer": ISSUER, "audience": AUDIENCE, "organization_claim": ""},
    ],
    ids=["no-issuer", "no-audience", "hmac", "none", "no-claim-name"],
)
def test_unsafe_configuration_is_refused(kwargs):
    with pytest.raises(OIDCConfigurationError):
        OIDCVerifier(**kwargs)


# ----------------------------------------------------------------------
# get_user
# ----------------------------------------------------------------------


def _patch_get_user(monkeypatch, *, identity=None, error=None, user=None, org=None):
    user = user or SimpleNamespace(id=7, email=None, selected_organization_id=None)
    org = org or SimpleNamespace(id=3, provider_id="acme")
    verifier = SimpleNamespace(
        verify=AsyncMock(return_value=identity, side_effect=error)
    )
    db = SimpleNamespace(
        get_or_create_user_by_provider_id=AsyncMock(return_value=(user, False)),
        get_or_create_organization_by_provider_id=AsyncMock(return_value=(org, False)),
        add_user_to_organization=AsyncMock(),
        update_user_selected_organization=AsyncMock(),
        update_user_email=AsyncMock(),
    )
    bootstrap = AsyncMock()
    monkeypatch.setattr(auth_depends, "AUTH_PROVIDER", "oidc")
    monkeypatch.setattr(auth_depends, "get_oidc_verifier", lambda: verifier)
    monkeypatch.setattr(auth_depends, "db_client", db)
    monkeypatch.setattr(auth_depends, "ensure_organization_bootstrapped", bootstrap)
    monkeypatch.setattr(auth_depends, "capture_event", lambda *a, **k: None)
    return SimpleNamespace(user=user, org=org, db=db, bootstrap=bootstrap)


async def test_get_user_maps_subject_and_organization(monkeypatch):
    ctx = _patch_get_user(
        monkeypatch,
        identity=OIDCIdentity("user-1", "acme", "Ana@Example.test"),
    )

    user = await auth_depends.get_user(authorization="Bearer token")

    assert user is ctx.user
    assert user.selected_organization_id == 3
    assert user.email == "ana@example.test"
    ctx.db.get_or_create_user_by_provider_id.assert_awaited_once_with("user-1")
    ctx.db.get_or_create_organization_by_provider_id.assert_awaited_once_with(
        org_provider_id="acme", user_id=7
    )
    ctx.db.add_user_to_organization.assert_awaited_once_with(7, 3)
    ctx.db.update_user_selected_organization.assert_awaited_once_with(7, 3)
    ctx.db.update_user_email.assert_awaited_once_with(7, "Ana@Example.test")
    ctx.bootstrap.assert_awaited_once_with(3, created_by="user-1")


async def test_get_user_follows_the_token_when_the_organization_changes(monkeypatch):
    """Same subject, another organization: the token decides, not the stored row."""
    ctx = _patch_get_user(
        monkeypatch,
        identity=OIDCIdentity("user-1", "globex"),
        user=SimpleNamespace(id=7, email=None, selected_organization_id=3),
        org=SimpleNamespace(id=9, provider_id="globex"),
    )

    user = await auth_depends.get_user(authorization="Bearer token")

    assert user.selected_organization_id == 9
    ctx.db.add_user_to_organization.assert_awaited_once_with(7, 9)


async def test_get_user_does_not_rewrite_an_unchanged_mapping(monkeypatch):
    ctx = _patch_get_user(
        monkeypatch,
        identity=OIDCIdentity("user-1", "acme"),
        user=SimpleNamespace(
            id=7, email="ana@example.test", selected_organization_id=3
        ),
    )

    await auth_depends.get_user(authorization="Bearer token")

    ctx.db.add_user_to_organization.assert_not_awaited()
    ctx.db.update_user_selected_organization.assert_not_awaited()
    ctx.db.update_user_email.assert_not_awaited()


async def test_get_user_survives_an_email_already_taken(monkeypatch):
    ctx = _patch_get_user(
        monkeypatch, identity=OIDCIdentity("user-1", "acme", "taken@example.test")
    )
    ctx.db.update_user_email.side_effect = RuntimeError("unique violation")

    user = await auth_depends.get_user(authorization="Bearer token")

    assert user.email is None
    assert user.selected_organization_id == 3


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (OIDCTokenError("bad"), 401),
        (OIDCOrganizationError("two"), 403),
        (OIDCKeysUnavailableError("down"), 503),
        (OIDCConfigurationError("wrong issuer"), 503),
    ],
)
async def test_get_user_maps_verification_failures_to_http(monkeypatch, error, status):
    ctx = _patch_get_user(monkeypatch, error=error)

    with pytest.raises(HTTPException) as raised:
        await auth_depends.get_user(authorization="Bearer token")

    assert raised.value.status_code == status
    ctx.db.get_or_create_user_by_provider_id.assert_not_awaited()


async def test_get_user_requires_a_token(monkeypatch):
    _patch_get_user(monkeypatch, identity=OIDCIdentity("user-1", "acme"))

    with pytest.raises(HTTPException) as raised:
        await auth_depends.get_user(authorization=None)

    assert raised.value.status_code == 401


async def test_api_key_still_takes_precedence(monkeypatch):
    ctx = _patch_get_user(monkeypatch, identity=OIDCIdentity("user-1", "acme"))
    api_key_user = SimpleNamespace(id=1)
    monkeypatch.setattr(
        auth_depends, "_handle_api_key_auth", AsyncMock(return_value=api_key_user)
    )

    user = await auth_depends.get_user(authorization="Bearer token", x_api_key="k")

    assert user is api_key_user
    ctx.db.get_or_create_user_by_provider_id.assert_not_awaited()
