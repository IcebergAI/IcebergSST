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
A shared extraction step turns supported attachment/file formats into text before detection:
plain/code/config as-is; PDF and office documents via a text extractor. Unsupported/binary
formats are skipped and counted. OCR is explicitly out of scope for MVP.

**Scanned content is untrusted input.** Attachments are attacker-editable and extraction
parsers are an attack surface on the engine. Mandatory guards: per-file size caps,
extraction timeouts, decompression-ratio limits (zip/office bombs), and failure isolation —
one hostile file fails that unit, never the task or the worker. See `docs/security.md`.
