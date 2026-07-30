"""What a connector hands to detection: normalized content units (#45).

Every source type has its own idea of what a "thing" is — a Confluence page with
comments and attachments, a file on a share, a Jira issue. Detection should not
know about any of that, so connectors flatten all of it into one shape: some text,
and enough locator to say where it came from.

The locator is the part that has to be right. It feeds the finding fingerprint
(ADR 0006), so it is split deliberately:

* :attr:`ContentUnit.locator` is **coarse and stable** — page id, attachment name.
  It is what identity is computed from, and it must not change when someone edits
  a paragraph. That is what makes an analyst's triage decision survive a re-scan.
* :attr:`ContentUnit.display` is everything else worth showing — the URL, the
  space, the title, the author. It is stored on the finding and shown in the UI,
  and it may change freely between scans without orphaning anything.

Getting that split wrong is expensive and quiet: put a URL that carries a version
parameter into the coarse half and every re-scan produces "new" findings while the
old ones auto-resolve, silently discarding triage history.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from iceberg_core.fingerprint import CoarseLocator

#: Keys the suppression path matches path globs against
#: (:data:`iceberg_core.suppression.LOCATOR_PATH_KEYS`). Connectors should
#: populate whichever of these make sense for their source, or analysts will have
#: nothing sensible to write a `path_glob` suppression against.
GLOB_FRIENDLY_KEYS = ("path", "url", "space", "title")


class ContentOrigin(StrEnum):
    """Which part of a resource a unit came from.

    Kept alongside the finding because it changes what an analyst does about it: a
    secret in a page body is someone's documentation, in a comment it is someone
    answering a question in a hurry, and in an attachment it is a file that was
    probably pasted from somewhere else.
    """

    BODY = "body"
    COMMENT = "comment"
    ATTACHMENT = "attachment"


@dataclass(frozen=True, slots=True)
class ContentUnit:
    """One piece of text to scan, and where it came from."""

    #: Stable identity. Feeds the fingerprint — never line, offset, or version.
    locator: CoarseLocator
    #: Extracted UTF-8 text. Never bytes: extraction happens before this point.
    text: str
    origin: ContentOrigin = ContentOrigin.BODY

    #: Display-only context — URL, space, title, author, media type. Stored on the
    #: finding and shown in the UI; changing it never affects identity.
    display: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # A unit whose text is bytes would be a decoding bug that surfaces later as
        # a regex TypeError deep inside detection, with no clue which connector
        # produced it.
        if not isinstance(self.text, str):  # pragma: no cover — defensive
            raise TypeError(f"ContentUnit.text must be str, got {type(self.text).__name__}")

    def resource_locator(self) -> dict[str, Any]:
        """The `resource_locator` blob stored on a finding.

        Both halves, flattened: the coarse identity so a finding can be traced back
        to what produced its fingerprint, and the display context so the UI has
        something to show. Coarse keys win on collision — a connector that puts
        ``resource_id`` in ``display`` must not be able to shadow the real one.
        """
        return {
            **self.display,
            "connector_type": self.locator.connector_type,
            "resource_id": self.locator.resource_id,
            "sub_resource": self.locator.sub_resource,
            "origin": self.origin.value,
        }
