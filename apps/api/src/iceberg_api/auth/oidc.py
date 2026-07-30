"""OIDC authorization-code client (ADR 0005).

Deliberately small and explicit rather than a framework integration: the parts
that matter for security are the ones worth being able to read in one sitting.

* **Authorization code with PKCE.** The code verifier never leaves this service,
  so an intercepted authorization code cannot be redeemed by anyone else.
* **`state` and `nonce`.** ``state`` (checked against the login cookie) stops a
  cross-site login being forced on a visitor; ``nonce`` (checked inside the ID
  token) stops a token minted for another session being replayed into ours.
* **ID token verified, not decoded.** Signature against the provider's JWKS, plus
  issuer, audience, and expiry. A token is never trusted for its claims alone.

The provider's discovery document and JWKS are fetched over HTTP and cached for
the process; both are injectable so tests can drive the real verification path
against a key they control.
"""

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx2
import jwt

DISCOVERY_PATH = "/.well-known/openid-configuration"
REQUEST_TIMEOUT_SECONDS = 10.0
SIGNING_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384")


class OidcError(Exception):
    """The provider misbehaved, or its response could not be trusted."""


@dataclass(frozen=True, slots=True)
class OidcConfig:
    """Everything needed to talk to one identity provider."""

    issuer: str
    client_id: str
    # Kept out of the repr: structlog and tracebacks both render values with repr,
    # and this object is the kind of thing that ends up logged as `config=...`. The
    # key-name redactor masks by key, so a secret nested in an object under a benign
    # key would otherwise pass through (the same reasoning as Credential.__repr__).
    client_secret: str = field(repr=False)
    redirect_url: str
    scopes: str = "openid profile email"


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """The subset of the discovery document this client uses."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> "ProviderMetadata":
        try:
            return cls(
                issuer=document["issuer"],
                authorization_endpoint=document["authorization_endpoint"],
                token_endpoint=document["token_endpoint"],
                jwks_uri=document["jwks_uri"],
            )
        except KeyError as exc:
            raise OidcError(f"discovery document is missing {exc.args[0]!r}") from exc


@dataclass(frozen=True, slots=True)
class IdentityClaims:
    """The verified identity of the person who just logged in."""

    subject: str
    email: str
    display_name: str
    #: Whether the provider vouches for the email (the ``email_verified`` claim).
    #: OIDC is explicit that ``email`` alone is not trustworthy; anything that
    #: grants privilege by address must check this flag.
    email_verified: bool = False


def new_pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def pkce_challenge(verifier: str) -> str:
    """S256 challenge — the only method worth offering."""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


class OidcClient:
    """A thin, cached client for one provider."""

    def __init__(
        self,
        config: OidcConfig,
        *,
        metadata: ProviderMetadata | None = None,
        jwks: dict[str, Any] | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._metadata = metadata
        self._jwks = jwks
        # An injected JWKS is authoritative (tests pin one); only a fetched JWKS
        # may be refreshed when a token names a key it does not contain.
        self._jwks_pinned = jwks is not None
        # Injected by tests so discovery and token exchange run their real code
        # against a scripted provider instead of the network.
        self._transport = transport

    @property
    def config(self) -> OidcConfig:
        return self._config

    async def metadata(self) -> ProviderMetadata:
        """Fetch (and cache) the provider's discovery document."""
        if self._metadata is None:
            document = await self._get_json(self._config.issuer.rstrip("/") + DISCOVERY_PATH)
            metadata = ProviderMetadata.from_document(document)
            if metadata.issuer.rstrip("/") != self._config.issuer.rstrip("/"):
                # A discovery document claiming a different issuer than the one
                # we asked about means we are not talking to who we think.
                raise OidcError(
                    f"discovery issuer {metadata.issuer!r} does not match "
                    f"configured issuer {self._config.issuer!r}"
                )
            self._metadata = metadata
        return self._metadata

    async def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        """Build the URL to send the browser to."""
        metadata = await self.metadata()
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self._config.client_id,
                "redirect_uri": self._config.redirect_url,
                "scope": self._config.scopes,
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        separator = "&" if "?" in metadata.authorization_endpoint else "?"
        return f"{metadata.authorization_endpoint}{separator}{query}"

    async def exchange_code(self, code: str, code_verifier: str) -> str:
        """Redeem an authorization code and return the raw ID token."""
        metadata = await self.metadata()
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._config.redirect_url,
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "code_verifier": code_verifier,
        }
        async with self._http() as client:
            response = await client.post(metadata.token_endpoint, data=form)
        if response.status_code != httpx2.codes.OK:
            # The body can echo the code or client secret, so it is never logged
            # or surfaced — only the status.
            raise OidcError(f"token endpoint returned HTTP {response.status_code}")

        payload = response.json()
        id_token = payload.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise OidcError("token response carried no id_token")
        return id_token

    async def verify_id_token(self, id_token: str, *, nonce: str) -> IdentityClaims:
        """Verify an ID token end to end and extract the identity."""
        metadata = await self.metadata()
        try:
            key = await self._signing_key(id_token)
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key,
                algorithms=list(SIGNING_ALGORITHMS),
                audience=self._config.client_id,
                issuer=metadata.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise OidcError("id_token failed verification") from exc

        if claims.get("nonce") != nonce:
            raise OidcError("id_token nonce does not match this login attempt")

        subject = str(claims["sub"])
        email = str(claims.get("email") or "")
        return IdentityClaims(
            subject=subject,
            email=email,
            # Providers vary in which of these they send; falling back to the
            # email (then the subject) keeps a user list readable either way.
            display_name=str(
                claims.get("name") or claims.get("preferred_username") or email or subject
            ),
            email_verified=claims.get("email_verified") is True,
        )

    async def _signing_key(self, id_token: str) -> jwt.PyJWK:
        """Resolve the JWKS key the token's ``kid`` names."""
        header = jwt.get_unverified_header(id_token)
        kid = header.get("kid")
        key = self._key_for(await self._jwk_set(), kid)
        if key is None and not self._jwks_pinned:
            # Key rotation: a cached JWKS can predate the key that signed this
            # token. One refetch closes the gap without letting a bad token
            # drive unbounded fetches.
            self._jwks = None
            key = self._key_for(await self._jwk_set(), kid)
        if key is None:
            raise OidcError(f"provider JWKS has no key for kid {kid!r}")
        return key

    async def _jwk_set(self) -> dict[str, Any]:
        if self._jwks is None:
            metadata = await self.metadata()
            self._jwks = await self._get_json(metadata.jwks_uri)
        return self._jwks

    async def _get_json(self, url: str) -> dict[str, Any]:
        async with self._http() as client:
            response = await client.get(url)
        if response.status_code != httpx2.codes.OK:
            raise OidcError(f"GET {url} returned HTTP {response.status_code}")
        document: dict[str, Any] = response.json()
        return document

    def _key_for(self, jwks: dict[str, Any], kid: str | None) -> jwt.PyJWK | None:
        for entry in jwks.get("keys", []):
            if kid is None or entry.get("kid") == kid:
                return jwt.PyJWK.from_dict(entry)
        return None

    def _http(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            timeout=REQUEST_TIMEOUT_SECONDS,
            # An identity provider that answers with a redirect is not one we
            # follow: it is where a token would be sent somewhere unintended.
            follow_redirects=False,
            transport=self._transport,
        )
