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

    Order matters and is not arbitrary: drop the elements that are pure metadata
    first (while their tags still identify them), unwrap CDATA before the tag
    stripper can mangle the ``]]>``, turn block elements into newlines while they
    are still recognisable, and only then remove what is left.
    """
    if not storage:
        return ""

    text = _DROPPED_ELEMENTS.sub(" ", storage)
    text = _CDATA.sub(r"\1", text)
    text = _BREAKS.sub("\n", text)
    text = _TAG.sub(" ", text)
    # Last, and only once: unescaping before tag-stripping would turn a written
    # `&lt;script&gt;` in someone's documentation into a tag and delete it.
    text = html.unescape(text)

    text = _SPACE_RUN.sub(" ", text)
    text = "\n".join(line.strip() for line in text.splitlines())
    return _BREAK_RUN.sub("\n", text).strip()


def body_text(resource: Mapping[str, Any]) -> str:
    """Pull the storage body out of a v2 page/comment payload and flatten it.

    Tolerant of a body that is missing: a page whose body did not come back is a
    page with no text to scan, not a task failure. ``view`` is accepted as a
    fallback because it is rendered HTML and flattens the same way; ADF
    (``atlas_doc_format``) is JSON and deliberately not handled here — running it
    through an XHTML flattener would produce structure, not prose.
    """
    body = resource.get("body")
    if not isinstance(body, dict):
        return ""

    for representation in ("storage", "view"):
        holder = body.get(representation)
        if isinstance(holder, dict) and holder.get("value"):
            return storage_to_text(str(holder["value"]))
    return ""
