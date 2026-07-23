# Connectors

A **connector** knows how to discover and fetch content from a source type and yield normalized
**content units** to the detection engine. Connectors run *inside the engine* (`packages/connectors`,
executed by `apps/engine`) — never in the API.

## Interface

```
class Connector(Protocol):
    def discover(self, source_spec) -> Iterable[TaskSpec]:
        """Split a source into scan-task units (e.g. one per Confluence space)."""

    def fetch(self, task_spec, credential) -> Iterable[ContentUnit]:
        """Yield content units for a task: page bodies, comments, extracted attachments."""
```

### ContentUnit
Normalized input to detection:
- `resource_locator` — stable identity (page id, URL, attachment name)
- `text` — extracted UTF-8 text
- `origin` — enum `body | comment | attachment`
- `metadata` — free-form (author, mime type, etc.)

`resource_locator` feeds directly into the finding fingerprint (ADR 0006), so it must be stable
across scans and **coarse** — page id + attachment name, never line/offset (offsets are display
metadata on the finding, not identity).

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
