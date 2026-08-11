"""Storage format flattened to scannable text (#48).

Two properties matter, and they pull against each other:

* **Markup must go**, because proximity between a keyword and a secret is a large
  part of how confidence is computed (ADR 0003), and thirty characters of tags
  between two things that are adjacent on screen costs findings.
* **Macro bodies must stay**, because a `code` block is where a pasted credential
  actually lands.

Most of the tests below are one of those two, and the interesting ones are where
naive stripping gets it wrong.
"""

from confluence_server import (
    SEEDED_SECRET,
    leaky_page_storage,
    storage_code_macro,
    storage_page,
)
from iceberg_connectors.confluence.storage import (
    body_text,
    storage_to_text,
    supported_body_text,
)

# ─── Markup goes ──────────────────────────────────────────────────────────────


def test_tags_are_replaced_rather_than_deleted() -> None:
    """Deleting them would join words: `<b>pass</b><i>word</i>` must not become
    "password" and invent a keyword nobody wrote."""
    assert storage_to_text("<b>alpha</b><i>beta</i>") == "alpha beta"


def test_block_elements_become_line_breaks() -> None:
    """So a redacted snippet in the UI reads like the page it came from. One break
    per boundary however many tags produced it — `</p><p>` and `<br/>` read alike."""
    assert storage_to_text(storage_page("first", "second")) == "first\nsecond"
    assert storage_to_text("<p>one<br/>two</p>") == "one\ntwo"
    assert storage_to_text("<ul><li>a</li><li>b</li></ul>") == "a\nb"


def test_a_table_row_stays_on_one_line() -> None:
    """The shape a credentials table has. Splitting cells would put a newline
    between "password" and its value and cost the proximity signal (ADR 0003)."""
    storage = "<table><tr><td>staging password</td><td>hunter2</td></tr></table>"

    assert storage_to_text(storage) == "staging password hunter2"


def test_entities_are_unescaped() -> None:
    assert storage_to_text("<p>a &amp; b &lt;c&gt; &quot;d&quot;</p>") == 'a & b <c> "d"'


def test_escaped_markup_in_prose_survives() -> None:
    """Someone documenting `&lt;script&gt;` wrote that text deliberately. Unescaping
    before stripping tags would turn it into a tag and delete it."""
    assert "<script>" in storage_to_text("<p>Avoid &lt;script&gt; in templates</p>")


def test_resource_references_are_dropped_whole() -> None:
    """`ri:*` elements name users, pages, and attachments — identifiers, not prose.
    Left in, an account id would read as a high-entropy secret."""
    storage = '<p>See <ri:page ri:content-title="Runbook" /> for details</p>'

    text = storage_to_text(storage)

    assert "Runbook" not in text
    assert "See" in text and "for details" in text


def test_macro_parameters_are_dropped() -> None:
    """A language name is configuration, not something a user typed."""
    text = storage_to_text(storage_code_macro("echo hello", language="python"))

    assert "python" not in text
    assert "echo hello" in text


# ─── Macro bodies stay ────────────────────────────────────────────────────────


def test_a_cdata_macro_body_is_kept() -> None:
    """The single most productive hiding place in the product. Stripping the macro
    wholesale would drop it."""
    text = storage_to_text(storage_code_macro(f"export TOKEN={SEEDED_SECRET}"))

    assert SEEDED_SECRET in text


def test_a_noformat_block_is_kept() -> None:
    storage = (
        '<ac:structured-macro ac:name="noformat">'
        f"<ac:plain-text-body><![CDATA[password: {SEEDED_SECRET}]]></ac:plain-text-body>"
        "</ac:structured-macro>"
    )

    assert SEEDED_SECRET in storage_to_text(storage)


def test_cdata_pseudo_tags_survive_the_tag_stripper_intact() -> None:
    """A CDATA body is literal text someone pasted, so a `<...>` in it is not markup.
    Keeping only the inner text is not enough: a pasted `<password>hunter2</password>`
    that loses its keyword costs the proximity signal confidence is scored on (ADR
    0003), which is most of why a code block is worth scanning at all."""
    text = storage_to_text(storage_code_macro("<config><token>abc123def456</token></config>"))

    assert "<config><token>abc123def456</token></config>" in text


def test_a_bracket_wrapped_value_in_a_code_block_is_not_deleted() -> None:
    """`token=<AKIA...>` reads as a tag to a stripper and vanishes whole — the
    secret, not just its markup."""
    text = storage_to_text(storage_code_macro(f"token=<{SEEDED_SECRET}>"))

    assert SEEDED_SECRET in text


def test_block_elements_inside_a_code_block_are_not_turned_into_line_breaks() -> None:
    """A pasted HTML template is content, not structure. Breaking on its `<p>` puts
    a newline between a keyword and the value beside it."""
    text = storage_to_text(storage_code_macro(f"<p>password: {SEEDED_SECRET}</p>"))

    assert f"<p>password: {SEEDED_SECRET}</p>" in text


# ─── The property the module exists for ───────────────────────────────────────


def test_a_keyword_and_its_secret_end_up_adjacent() -> None:
    """The argument for this module existing. In storage format the keyword and the
    secret are ~80 characters apart through markup; on screen they are neighbours,
    and proximity scoring has to see what the reader sees (ADR 0003)."""
    storage = leaky_page_storage()
    text = storage_to_text(storage)

    raw_gap = storage.index(SEEDED_SECRET) - storage.index("aws access key")
    flat_gap = text.index(SEEDED_SECRET) - text.index("aws access key")

    assert flat_gap < raw_gap
    assert flat_gap < 60


# ─── Robustness ───────────────────────────────────────────────────────────────


def test_an_unterminated_tag_does_not_eat_the_document() -> None:
    """Attacker-editable input: anyone who can edit a page controls these bytes.
    The tag pattern is bounded so a stray `<` cannot consume the rest of the page."""
    storage = "<p>before</p><" + "x" * 9000 + " <p>after</p>"

    text = storage_to_text(storage)

    assert "before" in text and "after" in text


def test_an_empty_body_is_empty_text() -> None:
    assert storage_to_text("") == ""
    assert supported_body_text({"body": {"storage": {"value": ""}}}) == (True, "")


def test_empty_elements_do_not_become_blank_lines() -> None:
    """A page built in the editor is full of them, and they are noise rather than
    structure — enough of them would push a keyword out of a rule's window."""
    assert storage_to_text("<p>a</p><p></p><p></p><p></p><p>b</p>") == "a\nb"
    assert storage_to_text("<p>a  \t  b</p>") == "a b"


# ─── Reading a v2 payload ─────────────────────────────────────────────────────


def test_the_storage_representation_is_preferred() -> None:
    resource = {
        "body": {
            "storage": {"value": "<p>from storage</p>"},
            "view": {"value": "<p>from view</p>"},
        }
    }

    assert body_text(resource) == "from storage"


def test_a_view_body_is_accepted_as_a_fallback() -> None:
    """Rendered HTML flattens the same way. An older deployment answering with it is
    not a reason to skip the page."""
    assert body_text({"body": {"view": {"value": "<p>rendered</p>"}}}) == "rendered"


def test_adf_is_not_flattened_as_xhtml() -> None:
    """ADF is JSON. Running it through an XHTML flattener yields structure, not
    prose — and reporting that as the page's text would scan the schema."""
    resource = {"body": {"atlas_doc_format": {"value": '{"type":"doc","content":[]}'}}}

    assert body_text(resource) == ""


def test_a_missing_body_is_no_text_rather_than_an_error() -> None:
    """The tolerant text helper remains convenient for display-only callers."""
    assert body_text({}) == ""
    assert body_text({"body": None}) == ""
    assert body_text({"body": {}}) == ""
    assert supported_body_text({}) == (False, "")
