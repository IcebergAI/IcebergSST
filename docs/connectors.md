# Connectors

A **connector** knows how to discover and fetch content from a source type and yield normalized
**content units** to the detection engine. Connectors run *inside the engine* (`packages/connectors`,
executed by `apps/engine`) — never in the API.

## Interface

```python
class Connector(Protocol):
    connector_type: str          # matches SourceType; part of every fingerprint

    def discover(self, connection, credential) -> Iterator[TaskSpec]:
        """Split a source into scan-task units (e.g. one per Confluence space)."""

    def fetch(self, connection, spec, credential, outcome) -> Iterator[ContentUnit]:
        """Yield content units for a task: page bodies, comments, extracted attachments."""
```

Both are **generators** by contract: a source with fifty thousand pages must not exist in memory
before detection sees the first one, and a task cancelled mid-fetch should stop rather than finish
and discard. `outcome` (a `FetchOutcome`) is passed *in* rather than returned for the same reason —
a caller that stops early still needs the tallies.

`registry.get(source_type)` resolves a connector for a lease. An unregistered type raises
`UnknownConnectorError` and fails the task: an engine that reported an empty source instead would
be indistinguishable from one that found no secrets.

**Errors split by operator response.** `CredentialError` means rotate the credential — retrying
will not help. Other `ConnectorError`s fail the task. A single unreadable page is neither: it is
counted in `FetchOutcome.failed` and the scan continues, because one bad page must not fail a scan
of fifty thousand.

### ContentUnit
Normalized input to detection:
- `locator` — a `CoarseLocator`: connector type + resource id + optional sub-resource
- `text` — extracted UTF-8 text (never bytes; extraction happens before this point)
- `origin` — enum `body | comment | attachment`
- `display` — free-form context (URL, space, title, author, media type)

**The split between `locator` and `display` is the thing to get right.** `locator` feeds the finding
fingerprint (ADR 0006), so it must be **coarse and stable** — page id + attachment name, never
line/offset, never a version parameter. `display` is everything else worth showing, stored on the
finding and free to change between scans.

Getting it wrong fails quietly rather than loudly: put a versioned URL in the coarse half and every
re-scan produces "new" findings while the previous ones auto-resolve, silently discarding the
analyst's triage history. `ContentUnit.resource_locator()` flattens both halves into the blob stored
on the finding, with the coarse keys winning on collision so `display` cannot shadow identity.

Populate at least one of `path`, `url`, `space`, or `title` in `display` — those are the keys a
`path_glob` suppression is matched against, and a connector populating none of them leaves analysts
unable to write one for that source.

## Two-phase execution (ADR 0009)
`discover()` also runs **in an engine**, not the API: a scan begins with a single discovery
task; the engine runs `discover()` and POSTs the resulting `TaskSpec`s back, and the API
persists + enqueues them as fetch tasks. The connector receives its credential (and the
fingerprint pepper) from the task **lease response** — never from env or the DB.

## Confluence connector (MVP)

**Target flavor: Confluence Cloud first** (REST v2, API tokens, cursor pagination). The
connector interface stays flavor-agnostic so a Server/Data Center variant (PATs, older REST)
can be added later without redesign.

- **Auth:** API token, delivered via the task lease (backed by the secret store). Credential
  never logged.
- **Discovery:** enumerate spaces (respecting the source's scope filter), page through content.
- **Content:**
  - page **bodies** (storage format → text)
  - page **comments**
  - **text-extractable attachments** — `txt`, source/config files, and PDF/office documents
    converted to text. **No image OCR** in MVP.
- **Pagination:** honor Confluence REST cursors; batch pages into scan tasks for parallel engines.
- **Rate limiting:** respect server limits; backoff on 429.

## Post-MVP connectors
- **Jira** — issues, comments, attachments (same interface, similar auth).
- **SMB/NFS file shares** — walk shares, stream files, apply the same text-extraction step.

## Text extraction

`extract_text(data, filename, limits=…, sandbox=…)` turns one file into text. It **never raises** —
every result is an `ExtractionOutcome`, because a connector iterating attachments must be able to
hand it anything and get an answer back:

| Outcome | Meaning |
|---|---|
| `extracted` | Text, possibly `truncated` at the output cap |
| `skipped_unsupported` | An image, a video, an archive — not an error, just not text |
| `skipped_binary` | Claimed to be text (`.txt`) and is not |
| `skipped_empty` | No text layer — a scanned PDF, since there is no OCR |
| `rejected_too_large` | Over the input cap; not parsed at all |
| `rejected_bomb` | An archive whose declared expansion is hostile |
| `failed_timeout` | The parser did not finish; its child was killed |
| `failed_parse` | The parser raised, or crashed its child |

`is_hostile` separates the ones worth an operator's attention from an ordinary PNG.

Formats: text/code/config by extension (an allowlist, so a new binary format nobody denylisted is
not decoded as garbage), ZIP-backed office documents through their XML parts, and PDF through its
text layer. **No OCR** — a scanned page is honestly empty rather than reported as clean-and-scanned.
Archives are skipped rather than walked: recursing means recursing into archives inside archives,
and the bomb defence would have to be right at every level rather than the top one.

### The guards
**Scanned content is untrusted input**, and extraction parsers are the engine's largest attack
surface (`docs/security.md`, boundary 4). Four guards, each for a failure the others miss:

- **Size caps**, before any parsing — the cheapest check, and it eliminates "large file exhausts
  memory" whole.
- **Decompression-ratio limits.** Office documents are ZIP archives and a few kilobytes of zeros
  expands to gigabytes. The compressed size is exactly the number that tells you nothing, so the
  archive's *declared* sizes are checked first — and the read is bounded anyway, because that
  declaration is attacker-controlled too.
- **Timeouts and crash isolation**, in a child process (`ExtractionSandbox`). A parser looping on a
  crafted cross-reference table cannot be caught with `try`, and cannot be bounded by a timer in the
  same process: `signal.alarm` only fires on the main thread, and a C extension in a tight loop
  never returns to the interpreter to notice it. A hang is a timeout and the child is killed; a
  segfault takes the child only. The pool is reused across files and replaced only when a child is
  actually lost.
- **Per-unit failure isolation** — the sum of the above. One hostile file costs one content unit.
