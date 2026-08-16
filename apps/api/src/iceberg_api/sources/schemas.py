"""Request and response shapes for sources and schedules.

Two rules shape these:

* **A credential never appears in a response.** Not the plaintext, and not the
  sealed ref either — a ref plus a leaked master key is a credential, and no client
  has any use for one. Responses carry ``has_credential`` instead.
* **The `connection` blob is validated per source type**, not stored as whatever
  JSON arrived. A typo in ``base_url`` should fail when an admin saves the source,
  not hours later inside a scan task.
"""

import re
import uuid
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Self
from urllib.parse import urlsplit, urlunsplit

from croniter import croniter
from iceberg_core.enums import ScanMode, SourceType
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from iceberg_api.schemas import UtcDatetime

#: Types an engine can actually scan. A source nothing can scan is worse than a
#: clear refusal, so this set and `CONNECTION_MODELS` below are kept in step.
SUPPORTED_SOURCE_TYPES = frozenset({SourceType.CONFLUENCE, SourceType.JIRA, SourceType.FILESHARE})

#: A Jira project key as Atlassian defines it. Mirrors the connector's own guard.
_JIRA_PROJECT_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,254}$")


class FileshareProtocol(StrEnum):
    """What backs a mounted share. Documentation, not behaviour — see
    :class:`FileshareConnection`."""

    SMB = "smb"
    NFS = "nfs"


class ConfluenceConnection(BaseModel):
    """Where a Confluence instance lives and how much of it is in scope.

    Every key the Confluence connector reads must be a field here: the blob is
    validated with ``extra="forbid"``, so a key this model omits is one no admin
    can store and no engine will ever receive — ``tests/test_source_connection_schema.py``
    holds the two in step.
    """

    model_config = ConfigDict(extra="forbid")

    #: Site root, e.g. ``https://example.atlassian.net`` — **without** ``/wiki``.
    #: The connector appends ``api_prefix`` (Cloud's default is ``/wiki/api/v2``)
    #: and builds UI links as ``base_url`` + ``/wiki`` + the relative link, so a
    #: base that already carries the context path yields ``/wiki/wiki/api/v2`` and
    #: every request from a source configured that way fails.
    base_url: str
    #: The Cloud account email. Its presence is what selects Basic ``email:token``
    #: auth; absent means the credential is a Server/DC PAT sent as a Bearer
    #: (docs/connectors.md § Auth).
    email: str | None = None
    #: Where the v2 API is mounted. Cloud's ``/wiki/api/v2`` is the connector's
    #: default; Server/DC deployments mount it elsewhere.
    api_prefix: str | None = None
    #: Space keys to scan. Empty means every space the credential can read.
    spaces: list[str] = Field(default_factory=list)
    include_comments: bool = True
    include_attachments: bool = True
    #: Off by default: personal spaces are every user's drafts, and scanning them
    #: should be a deliberate decision (docs/connectors.md).
    include_personal_spaces: bool = False

    @field_validator("base_url")
    @classmethod
    def _sane_base_url(cls, value: str) -> str:
        trimmed = value.strip().rstrip("/")
        if not trimmed.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        if " " in trimmed:
            raise ValueError("base_url must not contain spaces")
        return trimmed

    @field_validator("email")
    @classmethod
    def _clean_email(cls, value: str | None) -> str | None:
        # Empty selects Bearer auth exactly like an omitted field, so normalise
        # rather than store a blank that reads as "email configured".
        if value is None:
            return None
        return value.strip() or None

    @field_validator("api_prefix")
    @classmethod
    def _sane_api_prefix(cls, value: str | None) -> str | None:
        if value is None:
            return None
        trimmed = value.strip().rstrip("/")
        if not trimmed:
            return None
        if not trimmed.startswith("/") or " " in trimmed:
            # The client builds URLs as base_url + api_prefix + path; a prefix
            # missing its leading slash fails hours later inside a scan task.
            raise ValueError("api_prefix must be an absolute path like /wiki/api/v2")
        return trimmed

    @model_validator(mode="after")
    def _normalise_cloud_context(self) -> Self:
        """Store the Cloud site root, accepting the legacy ``/wiki`` example.

        The client appends the default ``/wiki/api/v2`` prefix.  Normalising only
        an exact ``/wiki`` context with the default prefix preserves Server/DC
        deployments whose custom context and API mount are intentional.
        """
        split = urlsplit(self.base_url)
        default_cloud_prefix = self.api_prefix in {None, "/wiki/api/v2"}
        if (
            default_cloud_prefix
            and split.path.rstrip("/") == "/wiki"
            and not split.query
            and not split.fragment
        ):
            self.base_url = urlunsplit((split.scheme, split.netloc, "", "", ""))
        return self

    @field_validator("spaces")
    @classmethod
    def _clean_spaces(cls, value: list[str]) -> list[str]:
        cleaned = [space.strip() for space in value if space.strip()]
        if len({space.casefold() for space in cleaned}) != len(cleaned):
            raise ValueError("spaces must not repeat")
        return cleaned


class JiraConnection(BaseModel):
    """Where a Jira instance lives and how much of it is in scope.

    Every key the Jira connector reads must be a field here: the blob is validated
    with ``extra="forbid"``, so a key this model omits is one no admin can store and
    no engine will ever receive — ``tests/test_source_connection_schema.py`` holds
    the two in step.

    There is deliberately **no free-text JQL field**. Operator-authored query text
    would be spliced into the connector's own windowed query, which would break both
    the reproducibility discovery depends on and the scope reconciliation the
    coverage manifest depends on.
    """

    model_config = ConfigDict(extra="forbid")

    #: Site root, e.g. ``https://example.atlassian.net``. The connector appends
    #: ``api_prefix`` (Cloud's default is ``/rest/api/3``) and builds UI links as
    #: ``base_url`` + ``/browse/KEY``.
    base_url: str
    #: The Cloud account email. Its presence is what selects Basic ``email:token``
    #: auth; absent means the credential is a Server/DC PAT sent as a Bearer.
    email: str | None = None
    #: Where the REST API is mounted. Cloud's ``/rest/api/3`` is the connector's
    #: default; Data Center serves ``/rest/api/2`` and is not certified yet.
    api_prefix: str | None = None
    #: Project keys to scan. Empty means every project the credential can read.
    projects: list[str] = Field(default_factory=list)
    include_comments: bool = True
    include_attachments: bool = True
    #: Off by default. Issue history holds values that were pasted and later
    #: removed — often the most productive hiding place in the product — but it
    #: multiplies the objects a scan enumerates, so it is a deliberate choice.
    include_history: bool = False
    #: Off by default: an archived project is usually deliberately out of scope.
    include_archived_projects: bool = False

    @field_validator("base_url")
    @classmethod
    def _sane_base_url(cls, value: str) -> str:
        trimmed = value.strip().rstrip("/")
        if not trimmed.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        if " " in trimmed:
            raise ValueError("base_url must not contain spaces")
        return trimmed

    @field_validator("email")
    @classmethod
    def _clean_email(cls, value: str | None) -> str | None:
        # Empty selects Bearer auth exactly like an omitted field, so normalise
        # rather than store a blank that reads as "email configured".
        if value is None:
            return None
        return value.strip() or None

    @field_validator("api_prefix")
    @classmethod
    def _sane_api_prefix(cls, value: str | None) -> str | None:
        if value is None:
            return None
        trimmed = value.strip().rstrip("/")
        if not trimmed:
            return None
        if not trimmed.startswith("/") or " " in trimmed:
            # The client builds URLs as base_url + api_prefix + path; a prefix
            # missing its leading slash fails hours later inside a scan task.
            raise ValueError("api_prefix must be an absolute path like /rest/api/3")
        return trimmed

    @field_validator("projects")
    @classmethod
    def _clean_projects(cls, value: list[str]) -> list[str]:
        cleaned = [key.strip() for key in value if key.strip()]
        if len({key.casefold() for key in cleaned}) != len(cleaned):
            raise ValueError("projects must not repeat")
        for key in cleaned:
            # Rejected here as well as in the connector. The connector validates
            # what the *server* named before it reaches JQL; this validates what an
            # operator typed, so a bad key is a 422 at save time rather than a
            # failed scan hours later.
            if not _JIRA_PROJECT_KEY.fullmatch(key):
                raise ValueError(
                    "project keys must start with a letter and contain only "
                    "letters, digits, and underscores"
                )
        return cleaned


class FileshareConnection(BaseModel):
    """A mounted SMB or NFS share, and how much of it is in scope (#145).

    The engine walks a **read-only mount**, not a protocol client: both SMB and
    NFS have kernel-side implementations an operator already knows how to
    configure, and re-implementing either would put a second authentication stack
    and a second credential store in the engine. So there is no host, no share
    name, and no credential here — the mount carries all three, and
    ``docs/connectors.md`` documents what has to be mounted where.

    Every key the fileshare connector reads must be a field here: the blob is
    validated with ``extra="forbid"``, so a key this model omits is one no admin
    can store and no engine will ever receive.
    """

    model_config = ConfigDict(extra="forbid")

    #: Which protocol backs the mount. Recorded rather than used: the walk is
    #: identical either way, and an operator debugging a permissions problem
    #: should not have to go and read the engine's fstab to find out which.
    protocol: FileshareProtocol
    #: Absolute path the share is mounted at *inside the engine*. Absolute
    #: because a relative one would resolve against whatever directory the worker
    #: happened to start in.
    mount_path: str = Field(min_length=1, max_length=1024)
    #: Subtrees within the mount, relative to it. Empty means the whole mount.
    #: Each becomes one fetch task, which is what parallelises a scan — and how
    #: an operator says "finance, not the entire file server".
    roots: list[str] = Field(default_factory=list, max_length=256)
    #: Glob filters over the mount-relative path. ``include`` empty means every
    #: file; ``exclude`` always wins, because the safe reading of an ambiguous
    #: rule set is the narrower one.
    include: list[str] = Field(default_factory=list, max_length=64)
    exclude: list[str] = Field(default_factory=list, max_length=64)
    #: Off by default. A share full of symlinks into other shares is how a scan
    #: quietly grows to cover systems nobody authorised — and the connector still
    #: refuses any resolved path outside the root even when this is on.
    follow_symlinks: bool = False
    #: Per-file ceiling, before anything is read. Bounded above by what
    #: extraction would refuse anyway, so raising it past that changes nothing.
    max_file_bytes: int = Field(default=32 * 1024 * 1024, ge=1, le=32 * 1024 * 1024)

    @field_validator("mount_path")
    @classmethod
    def _absolute_mount(cls, value: str) -> str:
        trimmed = value.strip().rstrip("/") or "/"
        if not trimmed.startswith("/"):
            raise ValueError("mount_path must be absolute, like /mnt/shares/finance")
        return trimmed

    @field_validator("roots", "include", "exclude")
    @classmethod
    def _clean_paths(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value if item.strip()]
        for item in cleaned:
            if item.startswith("/"):
                # A root is relative to the mount. An absolute one reads as "the
                # filesystem root", and the connector would refuse it later — a
                # 422 at save time is the better place to find out.
                raise ValueError("paths are relative to mount_path; drop the leading /")
            if ".." in PurePosixPath(item).parts:
                # The connector re-checks containment on the *resolved* path, so
                # this is not the control. It is the error message: an operator
                # who typed `../` should be told, not silently given nothing.
                raise ValueError("paths must not contain ..")
        return cleaned


CONNECTION_MODELS: dict[SourceType, type[BaseModel]] = {
    SourceType.CONFLUENCE: ConfluenceConnection,
    SourceType.JIRA: JiraConnection,
    SourceType.FILESHARE: FileshareConnection,
}


def validate_connection(source_type: SourceType, connection: dict[str, Any]) -> dict[str, Any]:
    """Validate a connection blob for its type and return it normalised.

    Raises ``ValueError`` for an unsupported type, and pydantic's
    ``ValidationError`` for a malformed one — the route turns either into a 422.
    """
    model = CONNECTION_MODELS.get(source_type)
    if model is None:
        raise ValueError(
            f"the {source_type.value} connector is not available yet; "
            f"supported types: {', '.join(sorted(t.value for t in SUPPORTED_SOURCE_TYPES))}"
        )
    return model.model_validate(connection).model_dump(mode="json")


class SourceCreate(BaseModel):
    """``POST /sources``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    type: SourceType
    connection: dict[str, Any]
    #: Stored sealed, through the secret store (ADR 0007). Write-only.
    credential: SecretStr | None = None
    enabled: bool = True


class SourceUpdate(BaseModel):
    """``PATCH /sources/{id}``. Omitted fields are left alone.

    Supplying ``credential`` rotates it. There is no way to *remove* a credential:
    a source that cannot authenticate cannot be scanned, so deleting the source is
    the honest operation.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    connection: dict[str, Any] | None = None
    credential: SecretStr | None = None
    enabled: bool | None = None


class SourceRead(BaseModel):
    """A source as the API exposes it — never including its credential."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    type: SourceType
    connection: dict[str, Any]
    enabled: bool
    #: Whether a credential is stored. The ref itself is deliberately not exposed.
    has_credential: bool
    created_at: UtcDatetime
    updated_at: UtcDatetime


class ConnectivityResult(BaseModel):
    """``POST /sources/{id}/test``: can we reach it with the stored credential?"""

    reachable: bool
    #: HTTP status the source answered with, when it answered at all.
    status_code: int | None = None
    #: A short, bounded explanation. Never echoes the credential or a response body.
    detail: str


class ScheduleCreate(BaseModel):
    """``POST /schedules``."""

    model_config = ConfigDict(extra="forbid")

    source_id: uuid.UUID
    cron: str = Field(min_length=1, max_length=128)
    enabled: bool = True
    #: What this cadence asks for. The API promotes it to a full scan whenever the
    #: source's watermarks cannot be trusted, so asking for incremental can make
    #: scans cheaper but can never stop reconciliation happening (#143).
    mode: ScanMode = ScanMode.FULL

    @field_validator("cron")
    @classmethod
    def _valid_cron(cls, value: str) -> str:
        expression = value.strip()
        if not croniter.is_valid(expression):
            raise ValueError("cron must be a valid 5-field expression, e.g. '0 3 * * *'")
        return expression


class ScheduleUpdate(BaseModel):
    """``PATCH /schedules/{id}``."""

    model_config = ConfigDict(extra="forbid")

    cron: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None
    mode: ScanMode | None = None

    @model_validator(mode="after")
    def _valid_cron(self) -> ScheduleUpdate:
        if self.cron is not None and not croniter.is_valid(self.cron.strip()):
            raise ValueError("cron must be a valid 5-field expression, e.g. '0 3 * * *'")
        return self


class ScheduleRead(BaseModel):
    """A schedule as the API exposes it."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    cron: str
    enabled: bool
    mode: ScanMode
    next_run_at: UtcDatetime | None
    last_run_at: UtcDatetime | None
    created_at: UtcDatetime
    updated_at: UtcDatetime
