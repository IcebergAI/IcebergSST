"""Turning attachments into text, safely (#46 — docs/security.md boundary 4).

Detection reads text. Sources hold files. This is the step between, and it is the
one place in the engine that hands attacker-supplied bytes to a parser — so the
guards are not hardening added later, they are what the module is.

Four of them, each for a failure the others do not cover:

* **Size caps**, before any parsing. The cheapest check, and it eliminates the
  whole class of "large file exhausts memory".
* **Decompression-ratio limits.** Office documents are ZIP archives, and a few
  kilobytes of zeros expands to gigabytes. The compressed size tells you nothing,
  so the archive's own declared sizes are checked before a byte is read.
* **Timeouts and crash isolation**, in a child process
  (:mod:`iceberg_connectors.sandbox`). A parser that loops forever or segfaults
  cannot be caught with ``try``; the only honest answer is somewhere it can die
  alone.
* **Per-unit failure isolation.** Every outcome below is a value, not an
  exception. One hostile file does not stop neighboring content from being
  scanned, but its incomplete count fails the fetch task so the API cannot
  reconcile findings against unread content.

What is *not* here: OCR (out of scope for MVP), and archive traversal. A ZIP
attachment is skipped rather than walked, because recursing into archives means
recursing into archives inside archives, and the bomb defence has to be right at
every level rather than the top one.
"""

import codecs
import zipfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath

import structlog

from iceberg_connectors.sandbox import ExtractionSandbox, SandboxCrashed, SandboxTimeout

logger = structlog.get_logger()

#: Extensions read as text directly. Deliberately a list of what is known to be
#: text rather than a list of what is known not to be: a new binary format nobody
#: added to a denylist would otherwise be decoded as text and scanned as garbage.
TEXT_EXTENSIONS = frozenset(
    {
        ".txt", ".md", ".rst", ".log", ".csv", ".tsv", ".json", ".yaml", ".yml",
        ".toml", ".ini", ".cfg", ".conf", ".properties", ".env", ".xml", ".html",
        ".htm", ".sql", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".py", ".rb",
        ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".go", ".rs", ".c", ".h",
        ".cpp", ".cs", ".php", ".pl", ".swift", ".scala", ".tf", ".tfvars",
        ".dockerfile", ".gradle", ".gitconfig", ".npmrc", ".netrc",
    }
)  # fmt: skip

#: ZIP-backed office formats, read through their document XML.
OFFICE_EXTENSIONS = frozenset({".docx", ".xlsx", ".pptx"})

PDF_EXTENSIONS = frozenset({".pdf"})

#: Filenames with no extension that are worth reading anyway — the config files
#: that most often carry credentials.
BARE_TEXT_NAMES = frozenset(
    {"dockerfile", "makefile", "procfile", ".env", ".npmrc", ".netrc", ".pgpass"}
)

#: Byte-order marks that name their own encoding, checked before the NUL heuristic
#: decides a file is binary. UTF-16 — Notepad's "Unicode", and what PowerShell's
#: redirection writes — carries a NUL every other byte, so a `passwords.txt`
#: exported from Windows would otherwise be skipped unread. UTF-32's marks come
#: first because the UTF-16 LE mark is a prefix of the UTF-32 LE one.
_BYTE_ORDER_MARKS = (
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


class ExtractionOutcome(StrEnum):
    """What happened to one file. Every one of these is a value, never a raise."""

    EXTRACTED = "extracted"
    #: An image, a video, an archive — not an error, just not scannable text.
    SKIPPED_UNSUPPORTED = "skipped_unsupported"
    #: Recognised as text, but the bytes are not.
    SKIPPED_BINARY = "skipped_binary"
    SKIPPED_EMPTY = "skipped_empty"
    REJECTED_TOO_LARGE = "rejected_too_large"
    #: A compression bomb: small on the wire, enormous once expanded.
    REJECTED_BOMB = "rejected_bomb"
    FAILED_TIMEOUT = "failed_timeout"
    #: The parser crashed the child process, or raised.
    FAILED_PARSE = "failed_parse"

    @property
    def is_text(self) -> bool:
        return self is ExtractionOutcome.EXTRACTED

    @property
    def is_hostile(self) -> bool:
        """Worth a log line and an operator's attention, unlike an ordinary skip."""
        return self in {
            ExtractionOutcome.REJECTED_BOMB,
            ExtractionOutcome.FAILED_TIMEOUT,
            ExtractionOutcome.FAILED_PARSE,
        }

    @property
    def is_incomplete(self) -> bool:
        """Whether requested text could not be scanned completely.

        Unsupported, binary, and empty files are policy skips.  These outcomes are
        different: the attachment was in scope and should have been readable, so a
        source-wide reconciliation may not treat its absent findings as remediated.
        """
        return self in {
            ExtractionOutcome.REJECTED_TOO_LARGE,
            ExtractionOutcome.REJECTED_BOMB,
            ExtractionOutcome.FAILED_TIMEOUT,
            ExtractionOutcome.FAILED_PARSE,
        }


@dataclass(frozen=True, slots=True)
class ExtractionLimits:
    """The bounds every extraction runs inside.

    Defaults are chosen to be generous for real documents and hostile to crafted
    ones. A 40 MB PDF is a rare but legitimate runbook; 400 MB of expanded XML
    from a 200 KB upload is not a document.
    """

    #: Refused before parsing. The file is not read past this.
    max_input_bytes: int = 32 * 1024 * 1024
    #: Extracted text is truncated here. A secret in the first 8 million characters
    #: is found; one after it is a risk accepted in exchange for a bounded worker.
    max_output_chars: int = 8 * 1024 * 1024
    #: Expanded-to-compressed ratio an archive may claim before it is a bomb.
    max_expansion_ratio: float = 200.0
    #: Members an office document may contain. A real one has tens.
    max_archive_members: int = 512
    #: Wall-clock per file, enforced by killing the child.
    timeout_seconds: float = 30.0


@dataclass(frozen=True, slots=True)
class Extracted:
    """The result of one extraction attempt."""

    outcome: ExtractionOutcome
    text: str = ""
    #: Why, for the log and the scan counts. Never the file's content.
    detail: str = ""
    truncated: bool = False


class BombError(Exception):
    """Raised inside the child when an archive's declared sizes are hostile."""


@dataclass(frozen=True, slots=True)
class _Parsed:
    """What one extractor produced, and whether it stopped at the output budget.

    A value rather than a bare string because only the extractor can tell the
    difference between a document that ended and one that was cut off: markup
    stripping shrinks the text, so the caller comparing lengths would call a
    truncated spreadsheet complete. Crosses the sandbox boundary, hence a plain
    module-level dataclass.
    """

    text: str
    truncated: bool = False


def extract_text(
    data: bytes,
    filename: str,
    *,
    limits: ExtractionLimits | None = None,
    sandbox: ExtractionSandbox | None = None,
) -> Extracted:
    """Extract scannable text from one file. Never raises.

    ``sandbox`` runs the parser in a child process; pass ``None`` for formats you
    are certain of, or in tests. Real callers should pass one — that is what makes
    a hanging parser cost a unit rather than a worker.
    """
    bounds = limits or ExtractionLimits()

    if len(data) > bounds.max_input_bytes:
        # Checked first and cheapest. Nothing parses a file this size.
        return Extracted(
            ExtractionOutcome.REJECTED_TOO_LARGE,
            detail=f"{len(data)} bytes exceeds the {bounds.max_input_bytes} byte cap",
        )
    if not data:
        return Extracted(ExtractionOutcome.SKIPPED_EMPTY)

    kind = classify(filename)
    if kind is None:
        return Extracted(
            ExtractionOutcome.SKIPPED_UNSUPPORTED,
            detail=f"no text extractor for {PurePosixPath(filename).suffix or 'this file'}",
        )

    extractor = _EXTRACTORS[kind]
    try:
        parsed = (
            extractor(data, bounds)
            if sandbox is None
            else sandbox.run(extractor, data, bounds, timeout=bounds.timeout_seconds)
        )
    except SandboxTimeout:
        return Extracted(ExtractionOutcome.FAILED_TIMEOUT, detail="parser timed out")
    except SandboxCrashed:
        return Extracted(ExtractionOutcome.FAILED_PARSE, detail="parser process crashed")
    except BombError as exc:
        return Extracted(ExtractionOutcome.REJECTED_BOMB, detail=str(exc))
    except _BinaryContent:
        return Extracted(ExtractionOutcome.SKIPPED_BINARY, detail="content is not text")
    except Exception as exc:
        # Any parser failure. Deliberately broad: the point is that no malformed
        # file can produce an exception this function does not turn into a value.
        # Exception text is attacker-influenced parser output and may echo document
        # plaintext, so only the code-owned exception class is retained.
        return Extracted(
            ExtractionOutcome.FAILED_PARSE, detail=f"{type(exc).__name__} parser failure"
        )

    if not parsed.text.strip():
        return Extracted(ExtractionOutcome.SKIPPED_EMPTY)

    truncated = parsed.truncated or len(parsed.text) > bounds.max_output_chars
    return Extracted(
        ExtractionOutcome.EXTRACTED,
        text=parsed.text[: bounds.max_output_chars],
        truncated=truncated,
        detail="output truncated" if truncated else "",
    )


def classify(filename: str) -> str | None:
    """Which extractor handles this file, or None if it is not scannable text."""
    name = PurePosixPath(filename).name.lower()
    suffix = PurePosixPath(name).suffix

    if name in BARE_TEXT_NAMES or (not suffix and name.startswith(".")):
        return "text"
    if suffix in TEXT_EXTENSIONS:
        return "text"
    if suffix in OFFICE_EXTENSIONS:
        return "office"
    if suffix in PDF_EXTENSIONS:
        return "pdf"
    return None


class _BinaryContent(Exception):
    """The bytes claimed to be text and are not."""


# ─── Extractors ───────────────────────────────────────────────────────────────
# Module-level functions, because the sandbox pickles them by name to reach the
# child. A closure or a lambda would not survive the trip.


def extract_plain_text(data: bytes, limits: ExtractionLimits) -> _Parsed:
    """Decode a text file, refusing anything that is really binary.

    A NUL byte in the first few kilobytes is the standard tell, and the reason to
    check: decoding a binary with ``errors="replace"`` produces megabytes of
    replacement characters that every entropy rule then chews through. A file that
    declares its encoding with a byte-order mark is believed first, because the
    NUL tell is exactly wrong for UTF-16.
    """
    for mark, encoding in _BYTE_ORDER_MARKS:
        if data.startswith(mark):
            return _Parsed(data.decode(encoding, errors="replace"))
    if b"\x00" in data[:8192]:
        raise _BinaryContent
    return _Parsed(data.decode("utf-8", errors="replace"))


def extract_office_text(data: bytes, limits: ExtractionLimits) -> _Parsed:
    """Read the XML parts of a ZIP-backed office document.

    The archive's *declared* sizes are checked before anything is decompressed —
    a bomb is small on the wire by construction, so the compressed size is exactly
    the number that tells you nothing.
    """
    import io
    import re

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        if len(members) > limits.max_archive_members:
            raise BombError(
                f"archive declares {len(members)} members, over the "
                f"{limits.max_archive_members} limit"
            )

        declared = sum(member.file_size for member in members)
        compressed = max(1, sum(member.compress_size for member in members))
        if declared > limits.max_output_chars * 4:
            raise BombError(f"archive expands to {declared} bytes, over the output cap")
        if declared / compressed > limits.max_expansion_ratio:
            raise BombError(
                f"archive expands {declared / compressed:.0f}x, over the "
                f"{limits.max_expansion_ratio:.0f}x limit"
            )

        pieces: list[str] = []
        budget = limits.max_output_chars
        truncated = False
        for member in members:
            if not member.filename.endswith(".xml") or member.is_dir():
                continue
            # Read bounded even after the declared-size check: the header is
            # attacker-controlled and may simply lie about file_size.
            with archive.open(member) as handle:
                raw = handle.read(budget + 1)
            if len(raw) > budget:
                # Honest and simply larger than what is left of the budget — a
                # 100k-row `sheet1.xml`, which passes every gate above and is the
                # file class this whole module exists for. Cutting it off scans the
                # start of a spreadsheet full of credentials; calling it a bomb
                # scans none of one, while an equally large .txt is truncated and
                # read. A member that understated itself cannot reach here: the
                # archive caps the read at the declared size and then fails the
                # CRC, which is a parse failure and already loud.
                raw, truncated = raw[:budget], True
            # Tags stripped rather than parsed into a tree: an XML parser on
            # untrusted input is another entity-expansion surface, and detection
            # only needs the text between the tags.
            text = re.sub(rb"<[^>]{0,4096}>", b" ", raw).decode("utf-8", errors="replace")
            pieces.append(text)
            budget -= len(text)
            if budget <= 0:
                truncated = True
                break

    return _Parsed(" ".join(pieces), truncated)


def extract_pdf_text(data: bytes, limits: ExtractionLimits) -> _Parsed:
    """Read the text layer of a PDF. No OCR — a scanned page yields nothing."""
    import io

    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    pieces: list[str] = []
    budget = limits.max_output_chars
    truncated = False
    for page in reader.pages:
        text = page.extract_text() or ""
        pieces.append(text)
        budget -= len(text)
        if budget <= 0:
            truncated = True
            break
    return _Parsed("\n".join(pieces), truncated)


_EXTRACTORS = {
    "text": extract_plain_text,
    "office": extract_office_text,
    "pdf": extract_pdf_text,
}
