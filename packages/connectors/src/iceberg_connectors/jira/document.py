"""Jira rich text → scannable text (#144).

Jira carries the same field in two entirely different encodings depending on which
API answered. Cloud's REST v3 returns **ADF** — Atlassian Document Format, a JSON
tree. Data Center and Cloud's v2 return **wiki markup**, a string. Both mean the
same prose, and detection wants only the prose.

**The encoding is decided by the payload, never by configuration.** :func:`issue_field_text`
dispatches on the shape of the value it was handed, so the connector never learns
which flavor it is talking to and an operator can never mis-declare it. That is the
same instinct as the credential rule in :mod:`iceberg_connectors.http`: flavor
differences belong at the edge that can actually observe them.

**ADF is the safer of the two to flatten**, which is worth saying because the
Confluence flattener next door goes to some length about parser risk. This input has
already been through ``json.loads`` under the client's byte cap, so there is no
markup to mis-parse, no entities to expand, and no unterminated delimiter to run a
regex off the end of. What it *does* have is unbounded nesting — depth is remote
input — so the walk is iterative with an explicit stack and a node budget. A
document past either bound is reported as **unread**, not as empty.

**Wiki markup keeps its code blocks.** ``{code}`` and ``{noformat}`` bodies are held
aside before anything else runs, for exactly the reason
:mod:`iceberg_connectors.confluence.storage` holds CDATA: that is where a pasted
credential lands, and it is text someone typed rather than markup to strip.

**Inline emphasis is deliberately left alone.** Stripping ``*bold*`` or ``-strike-``
would save one character of proximity distance and risks corrupting the very thing
being looked for — a token that begins or ends with ``_``, ``-`` or ``*`` would be
silently rewritten into a different string, and a rewritten secret is a missed
finding that nothing reports. Confluence strips tags because a tag is thirty
characters between a keyword and its value (ADR 0003); a one-character emphasis
marker is not worth that risk.

The transform is deliberately lossy and one-way. Nothing reconstructs the issue from
this; it exists to be scanned, and the finding points at the issue.
"""

import re
from collections.abc import Mapping, Sequence
from typing import Any

__all__ = ["adf_to_text", "issue_field_text", "wiki_to_text"]

#: A document richer than this is refused rather than partially flattened. Bounded
#: because the byte cap upstream still permits a great many small nodes, and a
#: half-walked tree returned as text would read downstream as "we scanned it".
MAX_ADF_NODES = 200_000

#: Nesting is remote input: a document can be authored with arbitrary depth. The
#: walk is iterative so depth costs no stack, but a bound still keeps one pathological
#: issue from spending a task's time.
MAX_ADF_DEPTH = 100

#: ADF nodes that end a line on screen. Everything else runs together, so text split
#: across marks (``bold``/plain/``code`` in one sentence) rejoins without gaps.
#:
#: ``tableCell`` and ``tableHeader`` are deliberately absent, exactly as they are in
#: the Confluence flattener: a row like "password | hunter2" must stay on one line,
#: because splitting it puts a newline between the keyword and the value and costs
#: the proximity signal that scores it (ADR 0003).
_ADF_BLOCKS = frozenset(
    {
        "blockquote",
        "bodiedSyncBlock",
        "bulletList",
        "codeBlock",
        "decisionItem",
        "decisionList",
        "expand",
        "extensionFrame",
        "heading",
        "layoutColumn",
        "layoutSection",
        "listItem",
        "mediaGroup",
        "mediaSingle",
        "nestedExpand",
        "orderedList",
        "panel",
        "paragraph",
        "rule",
        "syncBlock",
        "table",
        "tableRow",
        "taskItem",
        "taskList",
    }
)

#: Nodes whose visible text lives in ``attrs.text`` rather than in a child text node.
#: Worth collecting: a mention or a status sits inline, and dropping it would open a
#: gap between a keyword and the value beside it.
_ADF_ATTR_TEXT = frozenset({"emoji", "mention", "status"})

#: Cells hold *paragraphs* in ADF — there is no way to put bare text in one — so
#: leaving ``tableCell`` out of ``_ADF_BLOCKS`` is not enough on its own: the
#: paragraph inside would break the line anyway and put a newline between a keyword
#: and the value in the next cell. Everything below one of these emits spaces
#: instead of newlines, which is what actually keeps a row on one line.
_ADF_CELLS = frozenset({"tableCell", "tableHeader"})


class _DocumentTooComplex(Exception):
    """An ADF document exceeded a walk budget, so it was not read at all."""


def adf_to_text(document: Mapping[str, Any]) -> str:
    """Flatten one ADF document into text for detection.

    Iterative rather than recursive: nesting depth is chosen by whoever wrote the
    issue, and a recursive walker would turn a deeply nested document into a
    ``RecursionError`` mid-scan.

    Raises :class:`_DocumentTooComplex` past either budget. Callers reach this
    through :func:`issue_field_text`, which turns that into "unread" rather than
    into empty text.
    """
    parts: list[str] = []
    # Either a literal separator to emit, or a node paired with its depth and
    # whether it sits inside a table cell. A separator is pushed *before* a node's
    # children so it pops after them.
    stack: list[str | tuple[Mapping[str, Any], int, bool]] = [(document, 0, False)]
    budget = MAX_ADF_NODES

    while stack:
        item = stack.pop()
        if isinstance(item, str):
            parts.append(item)
            continue

        node, depth, in_cell = item
        budget -= 1
        if budget < 0:
            raise _DocumentTooComplex("document exceeded the node budget")
        if depth > MAX_ADF_DEPTH:
            raise _DocumentTooComplex("document exceeded the nesting budget")

        node_type = node.get("type")
        text = node.get("text")
        if isinstance(text, str):
            parts.append(text)
        elif isinstance(node_type, str) and node_type in _ADF_ATTR_TEXT:
            attrs = node.get("attrs")
            if isinstance(attrs, Mapping) and isinstance(attrs.get("text"), str):
                parts.append(str(attrs["text"]))

        # A URL is content, not decoration: a link whose target is a secret-bearing
        # URL is precisely a finding, and the visible text rarely repeats it.
        link = _adf_link(node)
        if link:
            parts.append(f" {link}")

        if isinstance(node_type, str) and node_type in _ADF_BLOCKS:
            stack.append(" " if in_cell else "\n")

        content = node.get("content")
        if isinstance(content, Sequence) and not isinstance(content, str | bytes):
            nested = in_cell or (isinstance(node_type, str) and node_type in _ADF_CELLS)
            for child in reversed(content):
                if isinstance(child, Mapping):
                    stack.append((child, depth + 1, nested))

    return _tidy("".join(parts))


def _adf_link(node: Mapping[str, Any]) -> str | None:
    """The URL a node points at, from a card's attrs or a ``link`` mark's href."""
    attrs = node.get("attrs")
    if isinstance(attrs, Mapping):
        url = attrs.get("url")
        if isinstance(url, str) and url:
            return url

    marks = node.get("marks")
    if isinstance(marks, Sequence) and not isinstance(marks, str | bytes):
        for mark in marks:
            if not isinstance(mark, Mapping) or mark.get("type") != "link":
                continue
            mark_attrs = mark.get("attrs")
            if isinstance(mark_attrs, Mapping):
                href = mark_attrs.get("href")
                if isinstance(href, str) and href:
                    return href
    return None


# ─── Wiki markup ──────────────────────────────────────────────────────────────

#: ``{code}``/``{noformat}`` blocks, held whole before anything strips around them.
#: The optional ``:java`` / ``:title=x`` parameter goes; the body is the point.
_WIKI_HELD_BLOCKS = re.compile(
    r"\{(code|noformat)(?::[^}\n]{0,4096})?\}(.{0,1000000}?)\{\1\}",
    re.IGNORECASE | re.DOTALL,
)

#: Stand-in for a held body while the strippers run. NUL is removed from the input
#: before any of these are issued, so nothing an issue author can type forges one.
_HELD = re.compile(r"\x00(\d+)\x00")

#: ``{{monospace}}`` — the delimiters go and the content stays. Handled before the
#: generic macro rule so ``{{`` is never read as a macro opening.
_WIKI_MONOSPACE = re.compile(r"\{\{(.{0,4096}?)\}\}", re.DOTALL)

#: ``[text|https://…]`` and a bare ``[https://…]``. Both keep the URL, because a
#: credential in a query string is a finding and the label never repeats it.
_WIKI_LINK = re.compile(r"\[([^\]|\n]{0,1024})\|([^\]\n]{0,2048})\]")
_WIKI_BARE_LINK = re.compile(r"\[([^\]|\n]{0,2048})\]")

#: Any remaining macro marker — ``{color:red}``, ``{panel}``, ``{quote}``, and their
#: closing halves. Bounded so an unterminated ``{`` cannot scan to the end of a large
#: description looking for a ``}`` that never comes.
_WIKI_MACRO = re.compile(r"\{[a-z][a-z0-9_-]{0,64}(?::[^}\n]{0,4096})?\}", re.IGNORECASE)

#: Line-leading structure: ``h1.`` through ``h6.`` and ``bq.``.
_WIKI_PREFIX = re.compile(r"^[ \t]{0,16}(?:h[1-6]|bq)\.[ \t]{0,4}", re.IGNORECASE | re.MULTILINE)

#: Line-leading list bullets: ``*``, ``#``, ``-`` runs and ``1.`` ordinals.
_WIKI_BULLET = re.compile(r"^[ \t]{0,16}(?:[*#]{1,8}|-{1,2}|\d{1,4}\.)[ \t]+", re.MULTILINE)

#: Table delimiters. Replaced with a space rather than a newline so a row keeps the
#: keyword and the value on one line — the same proximity rule as ``_ADF_BLOCKS``.
_WIKI_TABLE = re.compile(r"\|{1,2}")

_BREAK_RUN = re.compile(r"\n{2,}")
_SPACE_RUN = re.compile(r"[ \t\f\v]{2,}")


def wiki_to_text(value: str) -> str:
    """Flatten one wiki-markup field into text for detection.

    Order matters and is not arbitrary: set code bodies aside before anything can
    read them as markup, resolve the constructs that carry content (monospace,
    links), drop the ones that carry none, and put the code bodies back verbatim.
    """
    if not value:
        return ""

    held: list[str] = []

    def hold(match: re.Match[str]) -> str:
        # A code body is text someone pasted, so a `{color}` inside it is not a
        # macro and a `|` inside it is not a table. Stripping either would rewrite
        # a pasted credential into a different string.
        held.append(match[2])
        return f"\x00{len(held) - 1}\x00"

    text = _WIKI_HELD_BLOCKS.sub(hold, value.replace("\x00", ""))
    text = _WIKI_MONOSPACE.sub(r"\1", text)
    text = _WIKI_LINK.sub(r"\1 \2", text)
    text = _WIKI_BARE_LINK.sub(r"\1", text)
    text = _WIKI_MACRO.sub(" ", text)
    text = _WIKI_PREFIX.sub("", text)
    text = _WIKI_BULLET.sub("", text)
    text = _WIKI_TABLE.sub(" ", text)
    text = _HELD.sub(lambda match: held[int(match[1])], text)

    return _tidy(text)


def _tidy(text: str) -> str:
    """Collapse runs of whitespace without joining lines that were separate."""
    text = _SPACE_RUN.sub(" ", text)
    text = "\n".join(line.strip() for line in text.splitlines())
    return _BREAK_RUN.sub("\n", text).strip()


# ─── The fail-closed accessor ─────────────────────────────────────────────────


def issue_field_text(fields: Mapping[str, Any], key: str) -> tuple[bool, str]:
    """Return whether a readable field was present, plus its flattened text.

    Presence is separate from text for the same reason it is in
    :func:`~iceberg_connectors.confluence.storage.supported_body_text`, and the
    consequence of getting it wrong is the same: an explicit ``null`` is a
    legitimately empty field, while a field the response never carried is *unread*.
    Jira has several ordinary ways to hand back the latter — a screen scheme that
    omits the field, a ``fields=`` list that did not ask for it, a permission that
    hides it — and reporting one as empty text lets it reconcile an older finding
    as though someone had cleared the field.

    An unrecognised shape is unread rather than empty for the same reason: a value
    this code cannot flatten is one it did not read.
    """
    if key not in fields:
        return False, ""

    value = fields[key]
    if value is None:
        return True, ""
    if isinstance(value, str):
        return True, wiki_to_text(value)
    if isinstance(value, Mapping) and value.get("type") == "doc":
        try:
            return True, adf_to_text(value)
        except _DocumentTooComplex:
            # Too big to walk is not the same as empty, and must not read as clean.
            return False, ""
    return False, ""
