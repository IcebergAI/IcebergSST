"""Confluence storage format → scannable text (#48).

Storage format is XHTML with Confluence's own macro namespace layered on top. It
is *not* what a user sees, and the difference matters for detection in both
directions:

* Markup must go, or a rule that looks for a keyword near a secret sees
  ``<p>password</p><code>hunter2</code>`` — thirty characters of tags between two
  things that are adjacent on screen. Proximity scoring is a large part of how
  confidence is computed (ADR 0003), so the noise directly costs findings.
* Macro *parameters* must stay. A `code` macro's body and a `noformat` block are
  exactly where a pasted credential lands, and they arrive as CDATA inside
  ``<ac:plain-text-body>``. Stripping the macro wholesale would drop the most
  productive hiding place in the product.

**No XML parser.** The input is attacker-editable — anyone who can edit a page
controls these bytes — and an XML parser on untrusted input is an entity-expansion
and external-entity surface for no benefit here, since detection only wants the
text between the tags. `extract_office_text` makes the same call for the same
reason (#46, docs/security.md boundary 4).

The transform is deliberately lossy and one-way. Nothing reconstructs the page
from this; it exists to be scanned, and the finding points at the page.
"""

import html
import re
from collections.abc import Mapping
from typing import Any

#: Elements whose *content* is markup-adjacent noise rather than page text. Stripped
#: whole. `ac:parameter` carries macro configuration — a language name, a title —
#: none of which a user typed as prose.
_DROPPED_ELEMENTS = re.compile(
    r"<(ac:parameter|ri:[a-z-]+)\b[^>]{0,4096}>.{0,1000000}?</\1>|<ri:[a-z-]+\b[^>]{0,4096}/>",
    re.IGNORECASE | re.DOTALL,
)

#: CDATA wrappers around macro bodies. The delimiters go; the content is the point.
_CDATA = re.compile(r"<!\[CDATA\[(.*?)]]>", re.DOTALL)

#: Stand-in for a CDATA body while the tag stripper runs over everything around it.
#: NUL is not a legal XML character and is removed from the input before any of
#: these are issued, so nothing a page author can write forges one.
_HELD = re.compile(r"\x00(\d+)\x00")

#: Any remaining tag. Bounded so a crafted unterminated `<` cannot make the regex
#: scan the rest of a large document looking for a `>` that never comes.
_TAG = re.compile(r"<[^>]{0,4096}>")

#: Elements that end a line on screen. Replaced with a newline rather than a space
#: so that "line" boundaries in the scanned text roughly match what a reader sees,
#: which is what makes a redacted snippet legible in the UI.
#:
#: Table *cells* are deliberately absent: a row like "password | hunter2" must stay
#: on one line, because splitting it puts a newline between the keyword and the
#: value and costs the proximity signal that scores it (ADR 0003).
_BREAKS = re.compile(
    r"</?(p|br|div|li|tr|h[1-6]|pre|blockquote|ac:structured-macro)\b[^>]{0,4096}>",
    re.IGNORECASE,
)

#: One break per boundary, however many tags produced it. An open-plus-close pair
#: (`</p><p>`) and a self-closing `<br/>` should read the same, and blank runs from
#: empty elements are noise rather than structure.
_BREAK_RUN = re.compile(r"\n{2,}")
_SPACE_RUN = re.compile(r"[ \t\f\v]{2,}")


def storage_to_text(storage: str) -> str:
    """Flatten one storage-format body into text for detection.

    Order matters and is not arbitrary: set CDATA bodies aside before anything can
    read them as markup, drop the elements that are pure metadata (while their tags
    still identify them), turn block elements into newlines while they are still
    recognisable, remove what is left, and put the CDATA back.
    """
    if not storage:
        return ""

    held: list[str] = []

    def hold(match: re.Match[str]) -> str:
        # A CDATA body is text someone pasted, so a `<...>` inside it is not markup.
        # Stripping it deletes a pasted `<password>hunter2</password>` down to
        # `hunter2` — losing the keyword the proximity signal is scored on (ADR
        # 0003) — and removes a value written as `token=<AKIA...>` outright.
        held.append(match[1])
        return f"\x00{len(held) - 1}\x00"

    text = _CDATA.sub(hold, storage.replace("\x00", ""))
    text = _DROPPED_ELEMENTS.sub(" ", text)
    text = _BREAKS.sub("\n", text)
    text = _TAG.sub(" ", text)
    # Last, and only once: unescaping before tag-stripping would turn a written
    # `&lt;script&gt;` in someone's documentation into a tag and delete it.
    text = html.unescape(text)
    # After unescaping, because CDATA is literal by definition — an `&amp;` in a
    # code block is an ampersand-a-m-p, and the page said so.
    text = _HELD.sub(lambda match: held[int(match[1])], text)

    text = _SPACE_RUN.sub(" ", text)
    text = "\n".join(line.strip() for line in text.splitlines())
    return _BREAK_RUN.sub("\n", text).strip()


def supported_body_text(resource: Mapping[str, Any]) -> tuple[bool, str]:
    """Return whether a supported body was present, plus its flattened text.

    Presence is separate from text because an explicit empty body is a legitimate
    empty page, while a successful response that omits every requested
    representation is unread content.  Treating both as ``""`` lets the latter
    reconcile an older finding as though the page had been cleared.
    """
    body = resource.get("body")
    if not isinstance(body, Mapping):
        return False, ""

    for representation in ("storage", "view"):
        holder = body.get(representation)
        if isinstance(holder, Mapping) and "value" in holder and isinstance(holder["value"], str):
            return True, storage_to_text(holder["value"])
    return False, ""


def body_text(resource: Mapping[str, Any]) -> str:
    """Pull a supported v2 page/comment body out and flatten it.

    ``view`` is accepted as a fallback because it is rendered HTML and flattens
    the same way. ADF (``atlas_doc_format``) is JSON and deliberately not handled
    here — running it through an XHTML flattener would produce structure, not
    prose. Callers that need fail-closed coverage use :func:`supported_body_text`
    to distinguish missing from explicitly empty content.
    """
    return supported_body_text(resource)[1]
