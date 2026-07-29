"""The OIDC client: PKCE, discovery, token exchange, ID-token verification.

Every case here runs the real verification code against a provider whose signing
key the test controls (see ``conftest.FakeProvider``) — the point is that a token
which should not be trusted is in fact rejected, not that a stub said so.
"""

import base64
import hashlib
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
from iceberg_api.auth.oidc import (
    OidcClient,
    OidcConfig,
    OidcError,
    new_pkce_verifier,
    pkce_challenge,
)
from oidc_provider import CLIENT_ID, ISSUER, FakeProvider

REDIRECT_URL = "http://testserver/api/v1/auth/callback"
NONCE = "nonce-value"


def _config() -> OidcConfig:
    return OidcConfig(
        issuer=ISSUER,
        client_id=CLIENT_ID,
        client_secret="client-secret",  # scripted provider
        redirect_url=REDIRECT_URL,
    )


def _client(provider: FakeProvider) -> OidcClient:
    return OidcClient(_config(), transport=provider.transport())


def test_pkce_challenge_is_the_s256_of_the_verifier() -> None:
    verifier = new_pkce_verifier()

    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())

    assert pkce_challenge(verifier) == expected.decode().rstrip("=")
    assert "=" not in pkce_challenge(verifier)


def test_verifiers_are_unpredictable() -> None:
    assert new_pkce_verifier() != new_pkce_verifier()
    assert len(new_pkce_verifier()) >= 43  # RFC 7636 minimum


@pytest.mark.anyio
async def test_authorization_url_carries_state_nonce_and_pkce(provider: FakeProvider) -> None:
    url = await _client(provider).authorization_url(
        state="state-value", nonce=NONCE, code_challenge="challenge-value"
    )

    query = parse_qs(urlparse(url).query)
    assert urlparse(url).path == "/authorize"
    assert query["response_type"] == ["code"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["redirect_uri"] == [REDIRECT_URL]
    assert query["state"] == ["state-value"]
    assert query["nonce"] == [NONCE]
    assert query["code_challenge"] == ["challenge-value"]
    assert query["code_challenge_method"] == ["S256"]


@pytest.mark.anyio
async def test_discovery_is_fetched_once_and_cached(provider: FakeProvider) -> None:
    client = _client(provider)

    first = await client.metadata()
    second = await client.metadata()

    assert first is second
    assert first.token_endpoint == f"{ISSUER}/token"


@pytest.mark.anyio
async def test_a_discovery_document_claiming_another_issuer_is_rejected() -> None:
    """Otherwise a hijacked discovery URL redirects the whole flow elsewhere."""

    def handle(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            json={
                "issuer": "https://evil.example",
                "authorization_endpoint": "https://evil.example/authorize",
                "token_endpoint": "https://evil.example/token",
                "jwks_uri": "https://evil.example/jwks",
            },
        )

    client = OidcClient(_config(), transport=httpx2.MockTransport(handle))

    with pytest.raises(OidcError, match="does not match configured issuer"):
        await client.metadata()


@pytest.mark.anyio
async def test_an_incomplete_discovery_document_is_rejected() -> None:
    def handle(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"issuer": ISSUER})

    client = OidcClient(_config(), transport=httpx2.MockTransport(handle))

    with pytest.raises(OidcError, match="missing"):
        await client.metadata()


@pytest.mark.anyio
async def test_exchange_code_posts_the_verifier_and_returns_the_id_token(
    provider: FakeProvider,
) -> None:
    provider.id_token = provider.mint_id_token(nonce=NONCE)

    id_token = await _client(provider).exchange_code("auth-code", "verifier-value")

    assert id_token == provider.id_token
    assert provider.token_requests is not None
    sent = provider.token_requests[-1]
    assert sent["grant_type"] == "authorization_code"
    assert sent["code"] == "auth-code"
    assert sent["code_verifier"] == "verifier-value"
    assert sent["redirect_uri"] == REDIRECT_URL


@pytest.mark.anyio
async def test_a_failing_token_endpoint_raises_without_echoing_its_body(
    provider: FakeProvider,
) -> None:
    provider.token_status = 400

    with pytest.raises(OidcError) as raised:
        await _client(provider).exchange_code("auth-code", "verifier-value")

    assert "400" in str(raised.value)
    assert "invalid_grant" not in str(raised.value)


@pytest.mark.anyio
async def test_a_token_response_without_an_id_token_is_rejected(provider: FakeProvider) -> None:
    provider.id_token = ""

    with pytest.raises(OidcError, match="no id_token"):
        await _client(provider).exchange_code("auth-code", "verifier-value")


@pytest.mark.anyio
async def test_a_valid_id_token_yields_the_identity(provider: FakeProvider) -> None:
    token = provider.mint_id_token(nonce=NONCE, subject="oidc|alice", email="alice@example.test")

    claims = await _client(provider).verify_id_token(token, nonce=NONCE)

    assert claims.subject == "oidc|alice"
    assert claims.email == "alice@example.test"
    assert claims.display_name == "Alice Analyst"


@pytest.mark.anyio
async def test_display_name_falls_back_to_email_then_subject(provider: FakeProvider) -> None:
    with_email = provider.mint_id_token(nonce=NONCE, name=None)
    without_email = provider.mint_id_token(nonce=NONCE, name=None, email="")

    from_email = await _client(provider).verify_id_token(with_email, nonce=NONCE)
    from_subject = await _client(provider).verify_id_token(without_email, nonce=NONCE)

    assert from_email.display_name == "alice@example.test"
    assert from_subject.display_name == "oidc|alice"


@pytest.mark.anyio
async def test_a_token_for_another_audience_is_rejected(provider: FakeProvider) -> None:
    """A token minted for a different client is not a login for this one."""
    token = provider.mint_id_token(nonce=NONCE, audience="some-other-client")

    with pytest.raises(OidcError, match="failed verification"):
        await _client(provider).verify_id_token(token, nonce=NONCE)


@pytest.mark.anyio
async def test_a_token_from_another_issuer_is_rejected(provider: FakeProvider) -> None:
    token = provider.mint_id_token(nonce=NONCE, issuer="https://evil.example")

    with pytest.raises(OidcError, match="failed verification"):
        await _client(provider).verify_id_token(token, nonce=NONCE)


@pytest.mark.anyio
async def test_an_expired_token_is_rejected(provider: FakeProvider) -> None:
    token = provider.mint_id_token(nonce=NONCE, expires_in=timedelta(minutes=-5))

    with pytest.raises(OidcError, match="failed verification"):
        await _client(provider).verify_id_token(token, nonce=NONCE)


@pytest.mark.anyio
async def test_a_tampered_signature_is_rejected(provider: FakeProvider) -> None:
    header, payload, signature = provider.mint_id_token(nonce=NONCE).split(".")
    forged = f"{header}.{payload}.{signature[:-4]}AAAA"

    with pytest.raises(OidcError, match="failed verification"):
        await _client(provider).verify_id_token(forged, nonce=NONCE)


@pytest.mark.anyio
async def test_a_token_signed_by_an_unknown_key_is_rejected(provider: FakeProvider) -> None:
    token = provider.mint_id_token(nonce=NONCE, kid="a-key-we-never-published")

    with pytest.raises(OidcError, match="no key for kid"):
        await _client(provider).verify_id_token(token, nonce=NONCE)


@pytest.mark.anyio
async def test_a_token_for_another_login_attempt_is_rejected(provider: FakeProvider) -> None:
    """The nonce is what stops a token captured elsewhere being replayed here."""
    token = provider.mint_id_token(nonce="a-different-login")

    with pytest.raises(OidcError, match="nonce"):
        await _client(provider).verify_id_token(token, nonce=NONCE)
