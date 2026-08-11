"""Text extraction and its guards (#46).

Every outcome here is a *value*, never an exception. That is the property the
whole module is arranged around: a connector iterating attachments must be able to
hand each one to `extract_text` and get an answer, so that one hostile file costs
a unit rather than the task.
"""

import codecs
import io
import struct
import zipfile
from typing import Any

import pytest
from hostile import crashes, hangs
from iceberg_connectors.extraction import (
    ExtractionLimits,
    ExtractionOutcome,
    classify,
    extract_text,
)
from iceberg_connectors.sandbox import ExtractionSandbox

#: AWS's own documented example key — it has never authenticated anything.
SECRET_TEXT = "aws access key AKIAIOSFODNN7EXAMPLE in the runbook"


def _docx(body: str, *, member: str = "word/document.xml") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member, f'<?xml version="1.0"?><w:document><w:t>{body}</w:t></w:document>')
    return buffer.getvalue()


def _lying_docx(body: str, *, declared: int) -> bytes:
    """A .docx whose headers understate how much its member really expands to.

    `zipfile` always writes the truth, so the archive is built honestly and the two
    uncompressed-size fields — one in the local header, one in the central directory
    — are rewritten afterwards. That is what a hostile uploader with a hex editor
    does, and there is no other way to reach the branch: every size the writer
    produces is consistent by construction.
    """
    raw = bytearray(_docx(body))
    size = struct.pack("<I", declared)
    local = raw.index(b"PK\x03\x04") + 22
    central = raw.index(b"PK\x01\x02") + 24
    raw[local : local + 4] = size
    raw[central : central + 4] = size
    return bytes(raw)


def _blank_pdf() -> bytes:
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def _pdf(text: str) -> bytes:
    """A minimal PDF with a real text layer, assembled by hand.

    pypdf writes PDFs but cannot lay out text, and a fixture whose text layer is
    empty would not test that the text layer is read at all.
    """
    content = f"BT /F1 12 Tf 20 100 Td ({text}) Tj ET".encode()
    objects = [
        b"<</Type/Catalog/Pages 2 0 R>>",
        b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
        b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 200]/Contents 4 0 R"
        b"/Resources<</Font<</F1 5 0 R>>>>>>",
        b"<</Length %d>>stream\n" % len(content) + content + b"\nendstream",
        b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for index, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj" % index + body + b"endobj\n"
    start_xref = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1) + b"0000000000 65535 f \n"
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        start_xref,
    )
    return bytes(out)


# ─── Formats that extract ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "filename",
    ["notes.txt", "config.yaml", "settings.json", "deploy.sh", "main.py", ".env", "Dockerfile"],
)
def test_text_formats_extract_as_is(filename: str) -> None:
    result = extract_text(SECRET_TEXT.encode(), filename)

    assert result.outcome is ExtractionOutcome.EXTRACTED
    assert "AKIAIOSFODNN7EXAMPLE" in result.text


def test_an_office_document_yields_the_text_between_its_tags() -> None:
    result = extract_text(_docx(SECRET_TEXT), "runbook.docx")

    assert result.outcome is ExtractionOutcome.EXTRACTED
    assert "AKIAIOSFODNN7EXAMPLE" in result.text
    assert "<w:t>" not in result.text


def test_a_pdf_is_read_through_its_text_layer() -> None:
    result = extract_text(_pdf(SECRET_TEXT), "runbook.pdf")

    assert result.outcome is ExtractionOutcome.EXTRACTED
    assert "AKIAIOSFODNN7EXAMPLE" in result.text


def test_a_pdf_with_no_text_layer_yields_nothing_rather_than_pretending() -> None:
    """There is no OCR in MVP, so a scanned page is honestly empty. Reporting it
    as extracted-but-blank would make "this source is clean" mean two things."""
    result = extract_text(_blank_pdf(), "scan.pdf")

    assert result.outcome is ExtractionOutcome.SKIPPED_EMPTY


# ─── Formats that are skipped, and counted ────────────────────────────────────


@pytest.mark.parametrize("filename", ["photo.png", "clip.mp4", "archive.zip", "app.exe", "data"])
def test_unsupported_formats_are_skipped_without_error(filename: str) -> None:
    """Not an error — just not scannable text. The scan counts it and moves on."""
    result = extract_text(b"\x89PNG\r\n\x1a\n" + b"x" * 100, filename)

    assert result.outcome is ExtractionOutcome.SKIPPED_UNSUPPORTED
    assert result.text == ""


def test_a_binary_masquerading_as_text_is_skipped() -> None:
    """Decoding it with `errors="replace"` would produce megabytes of replacement
    characters for every entropy rule to chew through."""
    result = extract_text(b"\x00\x01\x02\x03" * 100, "notes.txt")

    assert result.outcome is ExtractionOutcome.SKIPPED_BINARY


@pytest.mark.parametrize(
    "data",
    [
        SECRET_TEXT.encode("utf-16"),
        codecs.BOM_UTF16_BE + SECRET_TEXT.encode("utf-16-be"),
        SECRET_TEXT.encode("utf-32"),
        SECRET_TEXT.encode("utf-8-sig"),
    ],
    ids=["utf-16-le", "utf-16-be", "utf-32", "utf-8-bom"],
)
def test_text_that_declares_its_encoding_is_decoded_rather_than_called_binary(
    data: bytes,
) -> None:
    """UTF-16 is Notepad's "Unicode" and what PowerShell's redirection writes, and it
    carries a NUL every other byte — so the binary tell is exactly wrong for it. A
    `passwords.txt` exported from Windows was skipped unread (#123)."""
    result = extract_text(data, "passwords.txt")

    assert result.outcome is ExtractionOutcome.EXTRACTED
    assert "AKIAIOSFODNN7EXAMPLE" in result.text
    assert "﻿" not in result.text  # ...and the mark itself is not scanned as text


def test_an_empty_file_is_skipped() -> None:
    assert extract_text(b"", "notes.txt").outcome is ExtractionOutcome.SKIPPED_EMPTY
    assert extract_text(b"   \n\t ", "notes.txt").outcome is ExtractionOutcome.SKIPPED_EMPTY


def test_an_archive_is_skipped_rather_than_walked() -> None:
    """Recursing into archives means recursing into archives inside archives, and
    the bomb defence would have to be right at every level."""
    assert classify("backup.zip") is None
    assert classify("backup.tar.gz") is None


# ─── Guards ───────────────────────────────────────────────────────────────────


def test_an_oversized_file_is_rejected_before_parsing() -> None:
    """The cheapest check, and it eliminates "large file exhausts memory" whole."""
    limits = ExtractionLimits(max_input_bytes=1024)

    result = extract_text(b"x" * 2048, "notes.txt", limits=limits)

    assert result.outcome is ExtractionOutcome.REJECTED_TOO_LARGE
    assert "1024 byte cap" in result.detail


def test_a_decompression_bomb_is_rejected_on_its_declared_size() -> None:
    """A few kilobytes of zeros expanding to 50 MB. The compressed size is exactly
    the number that tells you nothing, so the archive's own declaration is checked."""
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", b"\x00" * (50 * 1024 * 1024))

    result = extract_text(bomb.getvalue(), "bomb.docx")

    assert result.outcome is ExtractionOutcome.REJECTED_BOMB
    assert len(bomb.getvalue()) < 100 * 1024  # ...and it was tiny on the wire


def test_an_archive_with_too_many_members_is_rejected() -> None:
    """A real office document has tens of parts, not thousands."""
    many = io.BytesIO()
    with zipfile.ZipFile(many, "w") as archive:
        for index in range(50):
            archive.writestr(f"word/part{index}.xml", "<w:t>text</w:t>")

    result = extract_text(
        many.getvalue(), "many.docx", limits=ExtractionLimits(max_archive_members=10)
    )

    assert result.outcome is ExtractionOutcome.REJECTED_BOMB
    assert "members" in result.detail


def test_a_lying_zip_header_is_refused_loudly_rather_than_trusted() -> None:
    """The declared sizes every gate above is computed from are attacker-controlled.
    A member that understates itself cannot over-deliver — the archive caps the read
    at the declared size and fails the CRC — but the file must still be refused with
    an outcome an operator hears about, not read as far as the header allowed."""
    limits = ExtractionLimits(max_output_chars=64, max_expansion_ratio=10_000)

    result = extract_text(_lying_docx("A" * 200, declared=32), "liar.docx", limits=limits)

    assert result.outcome is ExtractionOutcome.FAILED_PARSE
    assert result.outcome.is_hostile
    assert result.text == ""


def test_an_honest_document_over_the_output_budget_is_truncated_not_called_a_bomb() -> None:
    """The distinction #121 turns on. A 100k-row `sheet1.xml` passes every
    declared-size gate and is simply larger than what is left of the budget;
    rejecting it scans none of a spreadsheet full of credentials, while an equally
    large .txt is truncated and scanned. The proportions here are the real ones: the
    archive total stays under the `max_output_chars * 4` gate, and the one member
    does not."""
    limits = ExtractionLimits(max_output_chars=64, max_expansion_ratio=10_000)

    result = extract_text(_docx("A" * 150), "big.docx", limits=limits)

    assert result.outcome is ExtractionOutcome.EXTRACTED
    assert result.truncated is True
    assert "A" in result.text


def test_extracted_text_is_truncated_at_the_output_cap() -> None:
    """A secret past the cap is missed; the alternative is an unbounded worker."""
    limits = ExtractionLimits(max_output_chars=100)

    result = extract_text(b"x" * 5000, "big.txt", limits=limits)

    assert result.outcome is ExtractionOutcome.EXTRACTED
    assert result.truncated is True
    assert len(result.text) == 100


# ─── Failure isolation, through the sandbox ───────────────────────────────────


def test_a_hanging_parser_becomes_a_timed_out_unit(monkeypatch: pytest.MonkeyPatch) -> None:
    """The acceptance criterion, at the level a connector sees it: a value, not a
    wedged task."""
    monkeypatch.setitem(
        __import__("iceberg_connectors.extraction", fromlist=["_EXTRACTORS"])._EXTRACTORS,
        "text",
        hangs,
    )

    with ExtractionSandbox() as sandbox:
        result = extract_text(
            b"anything",
            "notes.txt",
            limits=ExtractionLimits(timeout_seconds=0.5),
            sandbox=sandbox,
        )

    assert result.outcome is ExtractionOutcome.FAILED_TIMEOUT


def test_a_crashing_parser_becomes_a_failed_unit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        __import__("iceberg_connectors.extraction", fromlist=["_EXTRACTORS"])._EXTRACTORS,
        "text",
        crashes,
    )

    with ExtractionSandbox() as sandbox:
        result = extract_text(b"anything", "notes.txt", sandbox=sandbox)

    assert result.outcome is ExtractionOutcome.FAILED_PARSE


def test_a_malformed_document_fails_that_unit_only() -> None:
    """Not a zip at all, despite the extension."""
    result = extract_text(b"this is not a zip archive", "pretend.docx")

    assert result.outcome is ExtractionOutcome.FAILED_PARSE
    assert result.text == ""


def test_parser_exception_text_is_not_retained(monkeypatch: pytest.MonkeyPatch) -> None:
    canary = "plaintext-canary-must-not-survive"

    def raises_with_plaintext(_data: bytes, _limits: ExtractionLimits) -> Any:
        raise ValueError(canary)

    extraction = __import__("iceberg_connectors.extraction", fromlist=["_EXTRACTORS"])
    monkeypatch.setitem(extraction._EXTRACTORS, "text", raises_with_plaintext)

    result = extract_text(b"attacker controlled", "notes.txt")

    assert result.outcome is ExtractionOutcome.FAILED_PARSE
    assert result.detail == "ValueError parser failure"
    assert canary not in result.detail


def test_extraction_through_the_sandbox_matches_extraction_without_it() -> None:
    """Isolation must not change the answer, or the fast path and the safe path
    would find different secrets."""
    with ExtractionSandbox() as sandbox:
        isolated = extract_text(_docx(SECRET_TEXT), "runbook.docx", sandbox=sandbox)

    direct = extract_text(_docx(SECRET_TEXT), "runbook.docx")

    assert (isolated.outcome, isolated.text) == (direct.outcome, direct.text)


def test_hostile_outcomes_are_distinguishable_from_ordinary_skips() -> None:
    """An operator should hear about a bomb; they should not hear about a PNG."""
    assert ExtractionOutcome.REJECTED_BOMB.is_hostile
    assert ExtractionOutcome.FAILED_TIMEOUT.is_hostile
    assert not ExtractionOutcome.SKIPPED_UNSUPPORTED.is_hostile
    assert not ExtractionOutcome.EXTRACTED.is_hostile


def test_incomplete_outcomes_are_distinguishable_from_policy_skips() -> None:
    """Incomplete text may not justify reconciliation; an unsupported image may."""
    assert ExtractionOutcome.REJECTED_TOO_LARGE.is_incomplete
    assert ExtractionOutcome.REJECTED_BOMB.is_incomplete
    assert ExtractionOutcome.FAILED_TIMEOUT.is_incomplete
    assert ExtractionOutcome.FAILED_PARSE.is_incomplete
    assert not ExtractionOutcome.SKIPPED_UNSUPPORTED.is_incomplete
    assert not ExtractionOutcome.SKIPPED_BINARY.is_incomplete
    assert not ExtractionOutcome.SKIPPED_EMPTY.is_incomplete


def test_no_input_makes_extract_text_raise() -> None:
    """The contract a connector loop depends on, asserted over the nastiest inputs
    this suite can produce."""
    for data, filename in [
        (b"", "x.txt"),
        (b"\x00" * 10, "x.txt"),
        (b"not a zip", "x.docx"),
        (b"not a pdf", "x.pdf"),
        (b"\xff\xfe\xfd", "x.unknownext"),
        (_docx("ok"), "x.docx"),
    ]:
        assert extract_text(data, filename).outcome in set(ExtractionOutcome)
