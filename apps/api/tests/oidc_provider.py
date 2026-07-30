"""A scripted OIDC provider for the auth tests.

Not a stub of our client: a stand-in for the *provider*. Discovery, JWKS, and the
token endpoint are answered over an in-process transport, and ID tokens are really
RSA-signed, so the code under test runs its actual signature, issuer, audience,
and nonce checks. A test that proves a bad token is rejected is only worth
anything if the rejection came from the real verification path.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from iceberg_api.auth.oidc import ProviderMetadata

ISSUER = "https://idp.example.test"
CLIENT_ID = "iceberg-sst"
BOOTSTRAP_SUBJECT = "oidc|bootstrap-admin"
SIGNING_KID = "test-key-1"


@dataclass
class FakeProvider:
    """A scripted OIDC provider: discovery, JWKS, and a token endpoint."""

    private_key: rsa.RSAPrivateKey
    #: The next ID token the token endpoint will hand back.
    id_token: str = ""
    #: Status code for the token endpoint, so failures can be exercised too.
    token_status: int = 200
    token_requests: list[dict[str, str]] | None = None

    def __post_init__(self) -> None:
        self.token_requests = []

    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            issuer=ISSUER,
            authorization_endpoint=f"{ISSUER}/authorize",
            token_endpoint=f"{ISSUER}/token",
            jwks_uri=f"{ISSUER}/jwks",
        )

    @property
    def jwks(self) -> dict[str, Any]:
        public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key()))
        return {"keys": [{**public_jwk, "kid": SIGNING_KID, "use": "sig", "alg": "RS256"}]}

    def mint_id_token(
        self,
        *,
        subject: str = "oidc|alice",
        nonce: str,
        email: str = "alice@example.test",
        email_verified: bool | None = True,
        name: str | None = "Alice Analyst",
        audience: str = CLIENT_ID,
        issuer: str = ISSUER,
        expires_in: timedelta = timedelta(minutes=5),
        kid: str = SIGNING_KID,
    ) -> str:
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "sub": subject,
            "iss": issuer,
            "aud": audience,
            "iat": now,
            "exp": now + expires_in,
            "nonce": nonce,
            "email": email,
        }
        if email_verified is not None:
            claims["email_verified"] = email_verified
        if name is not None:
            claims["name"] = name
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": kid})

    def transport(self) -> httpx2.MockTransport:
        def handle(request: httpx2.Request) -> httpx2.Response:
            if request.url.path.endswith("/token"):
                assert self.token_requests is not None
                self.token_requests.append(dict(httpx2.QueryParams(request.content.decode())))
                if self.token_status != 200:
                    return httpx2.Response(self.token_status, json={"error": "invalid_grant"})
                return httpx2.Response(
                    200, json={"id_token": self.id_token, "token_type": "Bearer"}
                )
            if request.url.path.endswith("/jwks"):
                return httpx2.Response(200, json=self.jwks)
            if "openid-configuration" in request.url.path:
                return httpx2.Response(
                    200,
                    json={
                        "issuer": ISSUER,
                        "authorization_endpoint": f"{ISSUER}/authorize",
                        "token_endpoint": f"{ISSUER}/token",
                        "jwks_uri": f"{ISSUER}/jwks",
                    },
                )
            return httpx2.Response(404)

        return httpx2.MockTransport(handle)
