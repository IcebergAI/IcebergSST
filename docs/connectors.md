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
across scans.

## Confluence connector (MVP)

- **Auth:** API token / PAT, retrieved via the secret store. Credential never logged.
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
