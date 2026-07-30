"""The shipped rule pack, rule by rule, plus its false-positive rate (#43).

Three things are asserted here, and they pull against each other on purpose:

* **Every rule fires on its own secret type.** A rule nobody tests is a rule that
  quietly stops matching when someone tightens its regex.
* **Nothing fires on benign text.** The corpus below is the shapes that get
  mistaken for secrets in real documentation — git shas, UUIDs, checksums, base64
  of ordinary strings, example keys in prose.
* **Throughput is measured, not assumed.** The number is recorded in
  `docs/rules.md`; the assertion here is a floor loose enough to survive a shared
  CI runner, so it catches an accidental quadratic rather than a slow afternoon.

Fixtures are hand-written strings that *look* like credentials and are not: no
value here has ever authenticated anything.
"""

import time

import pytest
from iceberg_detect import detect, load_named_pack

PACK = load_named_pack()


def _fake(*parts: str) -> str:
    """Assemble a secret-shaped fixture so the whole literal is never in the file.

    Not obfuscation for its own sake. This pack detects the same shapes GitHub's
    push protection does, so a fixture written as one literal blocks the push that
    would add it — and "make the test value less realistic" is not available when
    the realism is what the rule matches on. Splitting the value keeps the fixture
    exact and the file pushable.
    """
    return "".join(parts)


#: rule id -> text that must produce exactly that rule.
POSITIVES: dict[str, str] = {
    "aws-access-key-id": "aws access key AKIAIOSFODNN7EXAMPLE in the runbook",
    "aws-secret-access-key": ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    "gcp-service-account-key": (
        '{"type": "service_account", "project_id": "demo", '
        '"private_key_id": "0123456789abcdef0123456789abcdef01234567"}'
    ),
    "gcp-api-key": "google maps api key AIzaSyD-1234567890abcdefghijklmnopqrstu",  # gitleaks:allow
    "azure-storage-account-key": (
        "azure storage DefaultEndpointsProtocol=https;AccountName=demo;"
        "AccountKey="  # gitleaks:allow
        "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJD"
    ),
    "azure-client-secret": (
        "azure tenant login, client_secret = 8Q~aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"
    ),
    "github-token": "github pat ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",  # gitleaks:allow
    "slack-token": "slack bot token " + _fake("xoxb-", "123456789012-", "abcdefghijklmnop"),
    "slack-webhook-url": (
        "notify slack via https://hooks.slack.com/services/T01234567/B01234567/"
        "abcdefghijklmnopqrstuvwx"
    ),
    "stripe-api-key": "stripe payment api key " + _fake("sk_", "live_", "a1B2c3D4e5F6g7H8i9J0k1L2"),
    "private-key-block": (
        "-----BEGIN RSA PRIVATE KEY-----\n"  # gitleaks:allow
        "MIIEowIBAAKCAQEAxyz0123456789abcdef\n"
        "-----END RSA PRIVATE KEY-----"
    ),
    "json-web-token": (
        "authorization bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRlbW8ifQ."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    ),
    "connection-string-password": (
        "database connection postgres://appuser:s3cr3t-p4ssw0rd@db.internal:5432/app"
    ),
    "basic-auth-header": (
        "curl -H 'Authorization: Basic ZGVtbzpodW50ZXIyMTIzNDU2Nzg5'"  # gitleaks:allow
        " https://api.example.test"
    ),
    "password-assignment": 'login credential password = "Tr0ub4dor&3xample"',
    "generic-high-entropy": "the service credential is 8f3Kd0aQ2mVx7Lp9Zr4Ts6Yw1Bn5Cj0H",
}

#: Text that looks secret-shaped and is not. Every one of these is something a
#: real Confluence space contains by the hundred.
BENIGN_CORPUS: tuple[str, ...] = (
    "The fix landed in commit 3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b on main.",
    "Correlation id 550e8400-e29b-41d4-a716-446655440000 appears in the logs.",
    "sha256 checksum e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "The base64 encoding of 'hello world' is aGVsbG8gd29ybGQ= for reference.",
    "Run `kubectl get pods -n production` and check the restart count.",
    "The quick brown fox jumps over the lazy dog, repeatedly and without comment.",
    "See the architecture decision record about authentication and session tokens.",
    "Our API returns 429 when you exceed the rate limit; back off and retry.",
    "Set the timeout to 30000 milliseconds in the deployment configuration.",
    "Docker image sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "The release notes for 2026.07.1 mention improved pagination on the findings list.",
    "Contact platform-team@example.test if the nightly scan has not completed by 09:00.",
    "Column names: created_at, updated_at, last_seen_scan_id, suppressed_by_id.",
    "The word 'password' appears in this sentence but nothing follows it.",
    "Base64 of the string 'configuration' is Y29uZmlndXJhdGlvbg== in the docs.",
    "A UUIDv7 like 01920000-0000-7000-8000-000000000000 sorts by creation time.",
    "Jenkins build #4821 finished in 12m34s with 0 failures and 3 skipped tests.",
    "Use `openssl rand -base64 32` to generate a new value, then store it in Vault.",
    'The ETag header was W/"6f8a9b2c3d4e5f60" on the cached response.',
    "Terraform state lock id 8a3f2b1c-4d5e-6f70-8192-a3b4c5d6e7f8 was released.",
)


@pytest.mark.parametrize("rule_id", sorted(POSITIVES))
def test_each_rule_fires_on_its_own_secret(rule_id: str) -> None:
    """A rule nobody tests stops matching the day someone tightens its regex."""
    result = detect(POSITIVES[rule_id], PACK)

    assert rule_id in {found.rule_id for found in result.secrets}, (
        f"{rule_id} did not fire; scored candidates: "
        f"{[(f.rule_id, round(f.confidence, 2)) for f in result.secrets]}"
    )


def test_every_rule_in_the_pack_has_a_positive_fixture() -> None:
    """The parametrised test above only covers rules someone remembered to add."""
    untested = sorted({rule.id for rule in PACK.rules} - set(POSITIVES))

    assert not untested, f"rules with no positive fixture: {', '.join(untested)}"


@pytest.mark.parametrize("rule_id", sorted(POSITIVES))
def test_each_positive_fixture_is_redacted(rule_id: str) -> None:
    """The fixture text contains a secret-shaped string; no snippet may repeat it."""
    for found in detect(POSITIVES[rule_id], PACK).secrets:
        assert found.secret not in found.redacted_snippet


@pytest.mark.parametrize("text", BENIGN_CORPUS)
def test_benign_text_produces_no_findings(text: str) -> None:
    """Each of these is something a real space contains by the hundred."""
    result = detect(text, PACK)

    assert result.secrets == [], (
        f"false positive on benign text: "
        f"{[(f.rule_id, round(f.confidence, 2)) for f in result.secrets]}"
    )


def test_the_measured_false_positive_rate_on_the_benign_corpus_is_zero() -> None:
    """The headline number for #43, asserted rather than reported in a comment.

    Zero is achievable because the corpus is small and hand-picked; the value of
    the assertion is that loosening a rule enough to match a git sha fails here
    rather than in an analyst's queue.
    """
    flagged = [text for text in BENIGN_CORPUS if detect(text, PACK).secrets]

    assert len(flagged) / len(BENIGN_CORPUS) == 0.0, f"flagged: {flagged}"


def test_a_secret_in_a_page_of_prose_is_still_found() -> None:
    """The realistic shape: one credential buried in a wiki page."""
    page = (
        "\n".join(BENIGN_CORPUS[:8])
        + "\n\nDeployment notes: set aws access key AKIAIOSFODNN7EXAMPLE in the runbook.\n\n"
        + "\n".join(BENIGN_CORPUS[8:])
    )

    result = detect(page, PACK)

    assert [found.rule_id for found in result.secrets] == ["aws-access-key-id"]
    assert "AKIAIOSFODNN7EXAMPLE" not in result.secrets[0].redacted_snippet


def test_the_generic_rule_needs_credential_wording() -> None:
    """It is the catch-all, and unqualified it reports every high-entropy token."""
    bare = "value 8f3Kd0aQ2mVx7Lp9Zr4Ts6Yw1Bn5Cj0H appears in the export"
    labelled = "api_key 8f3Kd0aQ2mVx7Lp9Zr4Ts6Yw1Bn5Cj0H appears in the export"

    assert detect(bare, PACK).secrets == []
    assert [f.rule_id for f in detect(labelled, PACK).secrets] == ["generic-high-entropy"]


def test_severities_are_assigned_where_they_belong() -> None:
    """A private key is not the same problem as a sample JWT in documentation."""
    by_id = {rule.id: rule.severity.value for rule in PACK.rules}

    assert by_id["private-key-block"] == "critical"
    assert by_id["aws-secret-access-key"] == "critical"
    assert by_id["github-token"] == "critical"
    assert by_id["json-web-token"] == "medium"
    assert by_id["generic-high-entropy"] == "medium"


def test_throughput_over_a_representative_page() -> None:
    """Benchmark for #43. The recorded figure lives in `docs/rules.md`.

    The floor is deliberately far below what a laptop manages: this catches a rule
    that turned quadratic, not a CI runner having a slow minute.
    """
    page = ("\n".join(BENIGN_CORPUS) + "\n") * 20  # ~35 KB, a large wiki page
    size_kb = len(page) / 1024

    started = time.perf_counter()
    detect(page, PACK)
    elapsed = time.perf_counter() - started

    throughput = size_kb / elapsed
    assert throughput > 100, f"detection managed only {throughput:.0f} KB/s over {size_kb:.0f} KB"
