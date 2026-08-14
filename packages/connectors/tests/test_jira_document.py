"""Jira rich text → scannable text (#144).

Two encodings of the same prose, and one accessor that must never confuse "the
field was empty" with "the field was not in the response". The recurring theme is
**what the flattener must not destroy**: a pasted credential inside a code block, a
row that puts a keyword beside its value, a token that happens to start with an
emphasis character.
"""

from typing import Any

import pytest
from iceberg_connectors.jira.document import (
    MAX_ADF_DEPTH,
    MAX_ADF_NODES,
    adf_to_text,
    issue_field_text,
    wiki_to_text,
)

SECRET = "AKIAIOSFODNN7EXAMPLE"


def _doc(*content: dict[str, Any]) -> dict[str, Any]:
    return {"type": "doc", "version": 1, "content": list(content)}


def _para(*content: dict[str, Any]) -> dict[str, Any]:
    return {"type": "paragraph", "content": list(content)}


def _text(value: str, **extra: Any) -> dict[str, Any]:
    return {"type": "text", "text": value, **extra}


# ─── ADF: structure goes, prose stays ─────────────────────────────────────────


def test_paragraphs_become_lines_and_marked_runs_rejoin() -> None:
    document = _doc(
        _para(_text("the "), _text("password", marks=[{"type": "strong"}]), _text(" is")),
        _para(_text(SECRET)),
    )

    assert adf_to_text(document) == f"the password is\n{SECRET}"


def test_a_code_block_keeps_its_body() -> None:
    document = _doc(
        _para(_text("deploy key")),
        {"type": "codeBlock", "attrs": {"language": "bash"}, "content": [_text(f"AWS={SECRET}")]},
    )

    assert f"AWS={SECRET}" in adf_to_text(document)


def test_a_table_row_keeps_the_keyword_beside_the_value() -> None:
    """The property the module exists for (ADR 0003).

    A newline between "password" and the value costs the proximity signal that
    scores the finding, so cells run together and only the row breaks.
    """
    row = {
        "type": "tableRow",
        "content": [
            {"type": "tableCell", "content": [_para(_text("password"))]},
            {"type": "tableCell", "content": [_para(_text(SECRET))]},
        ],
    }
    document = _doc({"type": "table", "content": [row]})

    flattened = adf_to_text(document)

    assert "\n" not in flattened.strip()
    assert "password" in flattened
    assert SECRET in flattened


def test_a_link_contributes_its_target_not_only_its_label() -> None:
    document = _doc(
        _para(
            _text(
                "the runbook",
                marks=[{"type": "link", "attrs": {"href": f"https://host/x?token={SECRET}"}}],
            )
        )
    )

    flattened = adf_to_text(document)

    assert "the runbook" in flattened
    assert SECRET in flattened


def test_an_inline_card_contributes_its_url() -> None:
    document = _doc(_para({"type": "inlineCard", "attrs": {"url": f"https://host/{SECRET}"}}))

    assert SECRET in adf_to_text(document)


def test_a_mention_keeps_its_visible_text() -> None:
    document = _doc(_para({"type": "mention", "attrs": {"id": "1", "text": "@ops"}}))

    assert "@ops" in adf_to_text(document)


# ─── ADF: robustness ──────────────────────────────────────────────────────────


def test_a_document_nested_past_the_depth_budget_is_unread_not_empty() -> None:
    node: dict[str, Any] = _text(SECRET)
    for _level in range(MAX_ADF_DEPTH + 5):
        node = {"type": "paragraph", "content": [node]}

    assert issue_field_text({"description": _doc(node)}, "description") == (False, "")


def test_a_document_past_the_node_budget_is_unread_not_empty() -> None:
    document = _doc(_para(*[_text("x") for _ in range(MAX_ADF_NODES + 10)]))

    assert issue_field_text({"description": document}, "description") == (False, "")


@pytest.mark.parametrize(
    "document",
    [
        {"type": "doc"},
        {"type": "doc", "content": []},
        {"type": "doc", "content": "not a list"},
        {"type": "doc", "content": [None, 7, "text"]},
        {"type": "doc", "content": [{"type": "paragraph", "content": None}]},
    ],
)
def test_a_malformed_document_flattens_to_nothing_rather_than_raising(
    document: dict[str, Any],
) -> None:
    assert adf_to_text(document) == ""


# ─── Wiki markup ──────────────────────────────────────────────────────────────


def test_a_code_macro_body_survives_verbatim() -> None:
    """Including markup *inside* it, which is text somebody pasted rather than markup."""
    markup = "see below\n{code:java}\ntoken = {color:red}" + SECRET + "{color}\n{code}"

    flattened = wiki_to_text(markup)

    assert f"token = {{color:red}}{SECRET}{{color}}" in flattened


def test_a_noformat_block_survives_verbatim() -> None:
    assert SECRET in wiki_to_text("{noformat}" + SECRET + "{noformat}")


def test_decoration_macros_go_but_their_content_stays() -> None:
    flattened = wiki_to_text("{panel:title=Creds}password is " + SECRET + "{panel}")

    assert "password is" in flattened
    assert SECRET in flattened
    assert "{panel" not in flattened


def test_a_link_keeps_both_label_and_target() -> None:
    flattened = wiki_to_text(f"[the runbook|https://host/x?token={SECRET}]")

    assert "the runbook" in flattened
    assert SECRET in flattened


def test_headings_and_bullets_lose_only_their_markers() -> None:
    flattened = wiki_to_text(f"h2. Credentials\n* password {SECRET}\n")

    assert flattened == f"Credentials\npassword {SECRET}"


def test_a_wiki_table_row_keeps_the_keyword_beside_the_value() -> None:
    flattened = wiki_to_text(f"|password|{SECRET}|")

    assert "\n" not in flattened.strip()
    assert "password" in flattened
    assert SECRET in flattened


def test_monospace_delimiters_go_and_the_credential_stays_intact() -> None:
    assert wiki_to_text("{{" + SECRET + "}}") == SECRET


@pytest.mark.parametrize(
    "token",
    ["_leading_underscore_token_", "*starred*", "-dashed-", "ghp_abcDEF123", "xoxb-1-2-abc"],
)
def test_emphasis_markers_are_left_alone_so_a_token_is_never_rewritten(token: str) -> None:
    """A stripped marker silently changes the secret, and a changed secret is a miss.

    One character of proximity distance is not worth rewriting a credential.
    """
    assert token in wiki_to_text(f"key = {token}")


# ─── The two encodings never cross ────────────────────────────────────────────


def test_adf_is_never_flattened_as_wiki_markup() -> None:
    """The mirror of the Confluence flattener's refusal to read ADF as XHTML.

    Handing the JSON tree to the string path would emit its punctuation and keys as
    prose; handing a wiki string to the JSON path would raise. The accessor decides
    by shape, so neither can happen.
    """
    document = _doc(_para(_text(SECRET)))

    present, text = issue_field_text({"description": document}, "description")

    assert (present, text) == (True, SECRET)
    assert "type" not in text
    assert "paragraph" not in text


def test_wiki_markup_is_never_parsed_as_json() -> None:
    present, text = issue_field_text({"description": "{code}" + SECRET + "{code}"}, "description")

    assert present is True
    assert text == SECRET


# ─── Unread is not empty ──────────────────────────────────────────────────────


def test_a_field_the_response_never_carried_is_unread() -> None:
    assert issue_field_text({"summary": "x"}, "description") == (False, "")


def test_an_explicit_null_is_a_legitimately_empty_field() -> None:
    assert issue_field_text({"description": None}, "description") == (True, "")


@pytest.mark.parametrize("value", [7, [], {"type": "notdoc"}, {"content": []}, True])
def test_an_unrecognised_shape_is_unread_rather_than_empty(value: Any) -> None:
    """A value this code cannot flatten is one it did not read.

    Reporting it as empty text would let it reconcile an older finding as though
    somebody had cleared the field.
    """
    assert issue_field_text({"description": value}, "description") == (False, "")
