"""The connectivity probe itself (#32).

Runs the real request path against a scripted source, because what matters is what
goes *out* — one bounded request, no redirect followed, no credential in anything
that comes back.
"""

import base64

import httpx2
import pytest
from iceberg_api.sources.probe import ProbeError, authorization_header, probe_source
from iceberg_core.enums import SourceType
from iceberg_core.models import Source
from pydantic import SecretStr

BASE_URL = "https://example.atlassian.net"
BASIC_CREDENTIAL = SecretStr("admin@example.test:api-token")
BEARER_CREDENTIAL = SecretStr("a-personal-access-token")


def _source(
    base_url: str | None = BASE_URL, source_type: SourceType = SourceType.CONFLUENCE
) -> Source:
    connection = {"base_url": base_url} if base_url is not None else {}
    return Source(name="probe-target", type=source_type, connection=connection)


def _transport(
    status_code: int = 200, *, capture: list[httpx2.Request] | None = None
) -> httpx2.MockTransport:
    def handle(request: httpx2.Request) -> httpx2.Response:
        if capture is not None:
            capture.append(request)
        return httpx2.Response(status_code, json={"accountId": "123"})

    return httpx2.MockTransport(handle)


def test_a_colon_separated_credential_becomes_basic_auth() -> None:
    """Confluence Cloud wants ``email:api_token``; a bare token is a Bearer."""
    header = authorization_header(BASIC_CREDENTIAL)

    scheme, encoded = header.split(" ", 1)
    assert scheme == "Basic"
    assert base64.b64decode(encoded).decode() == BASIC_CREDENTIAL.get_secret_value()
    assert (
        authorization_header(BEARER_CREDENTIAL) == f"Bearer {BEARER_CREDENTIAL.get_secret_value()}"
    )


def test_a_connection_email_selects_basic_auth_like_the_connector_does() -> None:
    """The documented Cloud convention: a bare API token plus ``email`` in the
    connection blob. The probe must authenticate exactly as a scan would
    (``Credential.header``), or `POST /sources/{id}/test` reports a false
    credential failure for a source whose scans work."""
    header = authorization_header(SecretStr("api-token"), email="admin@example.test")

    scheme, encoded = header.split(" ", 1)
    assert scheme == "Basic"
    assert base64.b64decode(encoded).decode() == "admin@example.test:api-token"


@pytest.mark.anyio
async def test_the_probe_reads_the_email_from_the_connection_blob() -> None:
    sent: list[httpx2.Request] = []
    source = Source(
        name="probe-target",
        type=SourceType.CONFLUENCE,
        connection={"base_url": BASE_URL, "email": "admin@example.test"},
    )

    await probe_source(source, SecretStr("api-token"), transport=_transport(capture=sent))

    scheme, encoded = sent[0].headers["authorization"].split(" ", 1)
    assert scheme == "Basic"
    assert base64.b64decode(encoded).decode() == "admin@example.test:api-token"


@pytest.mark.anyio
async def test_a_normalised_cloud_root_probes_the_scanners_v2_spaces_surface() -> None:
    sent: list[httpx2.Request] = []
    source = Source(
        name="probe-target",
        type=SourceType.CONFLUENCE,
        connection={"base_url": BASE_URL, "email": "admin@example.test"},
    )

    await probe_source(source, SecretStr("api-token"), transport=_transport(capture=sent))

    assert str(sent[0].url) == f"{BASE_URL}/wiki/api/v2/spaces?limit=1"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("connection", "expected"),
    [
        (
            {"base_url": f"{BASE_URL}/wiki", "email": "admin@example.test"},
            f"{BASE_URL}/wiki/api/v2/spaces?limit=1",
        ),
        (
            {
                "base_url": BASE_URL,
                "email": "admin@example.test",
                "api_prefix": "/confluence/api/v2",
            },
            f"{BASE_URL}/confluence/api/v2/spaces?limit=1",
        ),
        (
            {
                "base_url": "https://server.example.test/confluence",
                "api_prefix": "/rest/api/v2",
            },
            "https://server.example.test/confluence/rest/api/v2/spaces?limit=1",
        ),
    ],
)
async def test_probe_preserves_legacy_cloud_and_custom_server_contexts(
    connection: dict[str, str], expected: str
) -> None:
    sent: list[httpx2.Request] = []
    source = Source(name="probe-target", type=SourceType.CONFLUENCE, connection=connection)

    await probe_source(source, SecretStr("api-token"), transport=_transport(capture=sent))

    assert str(sent[0].url) == expected


@pytest.mark.anyio
async def test_a_successful_probe_hits_the_expected_url_with_the_credential() -> None:
    sent: list[httpx2.Request] = []

    result = await probe_source(_source(), BASIC_CREDENTIAL, transport=_transport(capture=sent))

    assert result.reachable is True
    assert result.status_code == 200
    assert str(sent[0].url) == f"{BASE_URL}/wiki/api/v2/spaces?limit=1"
    assert sent[0].headers["authorization"].startswith("Basic ")


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("status_code", "expected_fragment"),
    [
        (401, "rejected the stored credential"),
        (403, "rejected the stored credential"),
        (404, "check base_url"),
        (302, "redirected"),
        (500, "HTTP 500"),
    ],
)
async def test_failures_are_explained_without_echoing_anything(
    status_code: int, expected_fragment: str
) -> None:
    result = await probe_source(_source(), BASIC_CREDENTIAL, transport=_transport(status_code))

    assert result.reachable is False
    assert result.status_code == status_code
    assert expected_fragment in result.detail
    assert BASIC_CREDENTIAL.get_secret_value() not in result.detail


@pytest.mark.anyio
async def test_a_redirect_is_never_followed() -> None:
    """A source that answers 3xx must not be handed the credential twice."""
    seen: list[httpx2.Request] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(302, headers={"location": "https://evil.example/collect"})

    result = await probe_source(_source(), BASIC_CREDENTIAL, transport=httpx2.MockTransport(handle))

    assert result.reachable is False
    assert len(seen) == 1
    assert "evil.example" not in result.detail


@pytest.mark.anyio
async def test_a_connection_failure_is_reported_without_the_url() -> None:
    """Exception text can contain the URL, and for DNS failures it adds nothing."""

    def handle(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("getaddrinfo failed for example.atlassian.net")

    result = await probe_source(_source(), BASIC_CREDENTIAL, transport=httpx2.MockTransport(handle))

    assert result.reachable is False
    assert result.status_code is None
    assert "ConnectError" in result.detail
    assert "getaddrinfo" not in result.detail


@pytest.mark.anyio
async def test_probing_a_source_without_a_base_url_is_a_programming_error() -> None:
    with pytest.raises(ProbeError, match="base_url"):
        await probe_source(_source(base_url=None), BASIC_CREDENTIAL, transport=_transport())


@pytest.mark.anyio
async def test_a_source_reached_from_an_engine_has_no_probe_and_says_so() -> None:
    """A file share is a mount the API cannot see and holds no credential for
    (#145). "Connectivity OK" reported from the wrong machine is worse than no
    answer, so the refusal names the reason rather than saying "not yet"."""
    with pytest.raises(ProbeError, match="reached from an engine"):
        await probe_source(
            _source(source_type=SourceType.FILESHARE), BASIC_CREDENTIAL, transport=_transport()
        )
