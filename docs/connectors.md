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

**Target flavor: Confluence Cloud first** (REST v2, API tokens, cursor pagination). Lives in
`packages/connectors/src/iceberg_connectors/confluence/`, split three ways because the three parts
fail differently: `client.py` (cursors, credentials, throttling), `storage.py` (markup → text),
`connector.py` (spaces, pages, comments, attachments, locators).

**Auth is the one flavor-shaped seam.** Cloud authenticates an API token as HTTP Basic with the
account's email as the username — the token alone is not a bearer credential. Server/DC issues PATs
that are. Both arrive as one opaque string from the task lease; the `email` field in the source's
connection blob picks between them. That keeps Cloud specifics out of the `Connector` protocol,
which only knows "a credential".

The credential is never logged. `Credential.__repr__` is overridden rather than trusted, because
structlog and tracebacks both render values with `repr` and a token printed once into a log
aggregator has to be rotated.

**One space per fetch task, not one page.** Discovery yields a `TaskSpec` per space; pages are
enumerated lazily inside the fetch. Discovering every page of every space up front would turn the
fastest part of a scan into a serial prologue and produce a task table with a row per page.

**Cursors are opaque and followed verbatim.** v2 returns `_links.next`; rebuilding it from an offset
would skip or repeat results whenever content changes mid-scan — on a large space, missing secrets
with no sign it happened.

**429 is a normal answer.** A scan is exactly the workload that trips a rate limit. `Retry-After` is
honoured when the server sends a delta-seconds value (an HTTP date is not: it means trusting the
server's clock against ours, and skew gives either a busy loop or a stall). Waiting is bounded by
`RateLimitPolicy.max_wait_seconds` — past it the task fails and says to reduce engine concurrency,
because an engine cannot sit on a lease indefinitely.

### Content

| Origin | Source | Locator `sub_resource` |
|---|---|---|
| `body` | page storage format → text | *(none)* |
| `comment` | footer **and** inline comments | `comment:<id>` |
| `attachment` | text-extractable files via `extract_text` | `attachment:<filename>` |

Comments are separate units rather than appended to the body: they are separate things to fix, and
merging them would let one person's comment change the body's fingerprint. The attachment locator is
keyed on the **filename, not the attachment id** — replacing a file with a corrected version gives it
a new id, and keying on that would orphan the finding instead of updating it.

**Everything on a page shares the page's `path`/`url`.** Comments and attachments have no `webui`
link of their own; giving them a synthetic one would mean a `path_glob` an analyst wrote against a
page silently missed the comments and attachments on it — suppressing one finding out of three and
looking correct.

Personal spaces are excluded unless `include_personal_spaces` is set: they are every user's drafts,
they dominate the space count on a large site, and scanning them should be a deliberate decision.

Attachment size is checked twice — against the declared `fileSize` so an oversized file costs no
bandwidth, and against the bytes actually arriving, because that declaration comes from the same
place the file does. Both produce a *skip*, not a failure.

### Storage format → text

Storage format is XHTML plus Confluence's macro namespace, and is not what a user sees. Both
directions of the difference matter:

- **Markup must go.** `<p>password</p><code>hunter2</code>` puts thirty characters of tags between
  two things that are adjacent on screen, and proximity is a large part of how confidence is scored
  (ADR 0003). Table *cells* are deliberately not broken onto separate lines for the same reason — a
  credentials table row has to stay one line.
- **Macro bodies must stay.** A `code` block or `noformat` block is where a pasted credential lands,
  arriving as CDATA inside `<ac:plain-text-body>`. Stripping macros wholesale would drop the most
  productive hiding place in the product. Macro *parameters* (a language name) are dropped — nobody
  typed those as prose.

**No XML parser**, for the same reason `extract_office_text` uses none: the input is
attacker-editable, an XML parser on untrusted input is an entity-expansion surface, and detection
only wants the text between the tags.

### Testing it offline (#71)

`packages/connectors/tests/confluence_server.py` is a Confluence-shaped site served over
`httpx2.MockTransport` — the same in-process-server pattern as `apps/api/tests/oidc_provider.py`.
Chosen over recorded HTTP fixtures because:

1. Recording needs a live Cloud site and a token to record *from*. Nobody has one in CI, so the
   fixtures would be hand-written anyway — a mock server with worse ergonomics.
2. **Cursors are stateful.** A cassette replays a fixed sequence; it cannot answer "the second page
   of *this* cursor", so a pagination bug would replay green.
3. **429 is behaviour, not a payload.** Asserting the client waits what the server asked needs a
   server that decides to throttle.

What it does not do is validate requests against Atlassian's OpenAPI schema, so a field renamed
upstream passes here and fails in production. That risk is accepted — the alternative is no offline
test at all.

`tests/test_confluence_pipeline.py` runs the whole loop against it: lease → REST → storage→text →
detect → fingerprint → redact → pre-filter → submission, asserting a seeded secret surfaces redacted
and that fingerprints survive a re-scan of edited content.

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
