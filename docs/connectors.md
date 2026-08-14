# Connectors

A **connector** knows how to discover and fetch content from a source type and yield normalized
**content units** to the detection engine. Connectors run *inside the engine* (`packages/connectors`,
executed by `apps/engine`) — never in the API.

## Interface

The supported authoring surface is **Connector SDK v1**. Every connector declares immutable
metadata and capabilities, and registration rejects incompatible major versions. The concise
author guide, compatibility policy, reference implementation, and reusable conformance test are in
[`connector-sdk.md`](./connector-sdk.md).

```python
class Connector(Protocol):
    connector_type: str          # matches SourceType; part of every fingerprint
    metadata: ConnectorMetadata  # SDK version + explicit capabilities

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
will not help. Other `ConnectorError`s abort the task immediately. A per-unit failure is counted in
`FetchOutcome.failed` and scanning continues so findings from readable neighbors survive. The
engine then fails the fetch task and the API marks the scan partial; reconciliation and completion
notifications run only after a complete scan. This makes “could not read” distinct from “secret is
gone.” Policy exclusions such as images, unsupported formats, and genuinely empty text remain
ordinary skips, but they still make the coverage manifest partial and therefore cannot authorize
reconciliation.

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

For Cloud, configure `base_url` as the site root, for example
`https://example.atlassian.net`, **without** `/wiki`; the default `api_prefix` is
`/wiki/api/v2`. The API and client normalize the old exact `/wiki` form for compatibility. A
Server/DC context path is preserved when paired with its explicit custom `api_prefix`.

The credential is never logged. `Credential.__repr__` is overridden rather than trusted, because
structlog and tracebacks both render values with `repr` and a token printed once into a log
aggregator has to be rotated.

**One space per fetch task, not one page.** Discovery yields a `TaskSpec` per space; pages are
enumerated lazily inside the fetch. Discovering every page of every space up front would turn the
fastest part of a scan into a serial prologue and produce a task table with a row per page.

**Cursors are opaque and followed verbatim.** v2 returns `_links.next`; rebuilding it from an offset
would skip or repeat results whenever content changes mid-scan — on a large space, missing secrets
with no sign it happened.

**The context path comes from the server, not from us.** Cloud serves the API under `/wiki` and
returns `webui`/`downloadLink` relative to it, while Server/DC has no context path at all. The
client learns `_links.base` from responses and resolves relative links through it rather than
splicing a hardcoded `/wiki` — a guess that is wrong on one deployment shape either way, and whose
symptom is every attachment 404ing against a site that a fixture server happily serves.

**429 is a normal answer.** A scan is exactly the workload that trips a rate limit. `Retry-After` is
honoured when the server sends a delta-seconds value (an HTTP date is not: it means trusting the
server's clock against ours, and skew gives either a busy loop or a stall). Attachment downloads go
through the same retry path as the JSON calls: a download that failed while page fetches waited
politely would drop the attachment corpus, and "could not read" reads as "no secrets here". Waiting
is bounded by `RateLimitPolicy.max_wait_seconds` — past it the task fails and says to reduce engine
concurrency, because an engine cannot sit on a lease indefinitely. That failure propagates out of
per-page work rather than being counted as one skipped page, or the budget would be spent again on
every remaining page in the space.

### Content

| Origin | Source | Locator `sub_resource` |
|---|---|---|
| `body` | page storage format → text | *(none)* |
| `comment` | footer and inline comments, including cursor-paginated nested replies | `comment:<id>` |
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
place the file does. Both mark the task incomplete. So do malformed, bomb-like, timed-out, or
truncated requested documents; usable extracted prefixes are still scanned. Unsupported, binary,
and empty files remain policy skips.

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

`tests/test_confluence_pipeline.py` runs the engine-side loop against it: lease → REST →
storage→text → detect → fingerprint → redact → pre-filter → submission. The controlled-pilot
acceptance in `apps/api/tests/test_controlled_pilot.py` crosses the real signed OIDC, CSRF/RBAC,
engine lease/results, database ingest, triage/audit, outbox, and signed webhook boundaries as well.

## Jira

Cloud, through REST v3 (`packages/connectors/src/iceberg_connectors/jira/`). **Data Center is not
certified.** The seams exist — bearer PATs, a configurable `api_prefix`, and a wiki-markup text path
— but the fixture site models Cloud only, and issue search deliberately *refuses* Data Center's
offset-shaped response rather than paging it blindly.

**Auth** is the same flavor rule as Confluence, which is why one `Credential` serves both: an
`email` in the connection blob selects Basic `email:token` (Cloud API token); its absence sends the
credential as a bearer (Server/DC PAT).

**Scope** is a list of project keys, or empty for every project the credential can read. Archived
projects are excluded unless asked for. Content classes are chosen explicitly: comments and
attachments default on, **issue history defaults off**.

**Discovery windows a project by `created`.** One fetch task covers one project and one half-open
`created` range, with the bounds taken from that project's own oldest and newest issue rather than
from the clock — discovery must be reproducible, because the conformance kit runs it twice and
compares payloads. `created` is immutable, so an issue never migrates between windows and a boundary
cannot cause a skip or a double-scan on a rescan.

That windowing **is** the resume story: a reclaimed task re-runs one bounded window rather than a
whole project (ADR 0009 restarts a spec from the top), and windows that already finished are not
re-fetched. Within a window the connector pages by `nextPageToken`. This is *not* checkpointed
resume — a window reclaimed at 90% re-reads from its first issue — so the connector does **not**
declare `ConnectorCapability.CHECKPOINTS`. That contract is tracked separately in #143.

**Text.** Cloud v3 returns ADF (a JSON tree) and Data Center returns wiki markup (a string). Both
flatten to prose through one accessor that dispatches on the *shape of the payload*, never on
configuration, so an operator cannot mis-declare it. Rendered HTML is deliberately not requested,
for the same reason Confluence uses `storage` over `view`. A field the response never carried is
**unread**, not empty — conflating the two would let a missing field auto-resolve an older finding.

**A 403 is one object, not the site.** Jira permission schemes are per-project and per-issue, so
being refused one issue's comments is routine: it is counted, and the scan continues. Only a 401 and
an exhausted rate-limit budget stop the task. (Confluence is the opposite — its permissions are
space-shaped, so a 403 there means the credential.)

**Known coverage limits.**
- Issues the credential cannot browse are simply omitted by Jira, and the search endpoint no longer
  returns a total, so the connector *cannot* say "5000 existed, I read 4997". The unknown remainder
  becomes a scope gap, never an invented clean count.
- The upper window bound is pinned at the minute discovery observed, so content created during a
  scan belongs to the next one. Archived projects are requested explicitly rather than filtered out
  of the response, because Jira's project search returns live projects only by default.
- Issue history is capped per issue; the remainder is reported as a scope gap.
- Custom fields are not scanned. Only `summary`, `description`, `environment`, comments,
  attachments, and (opt-in) field history are.
- There is no free-text JQL option, by design: operator-authored query text spliced into the scan's
  own query would break both window reproducibility and scope reconciliation.
- A rate-limited scan produces a partial manifest, which resolves nothing and sends no completion
  notification. That is correct fail-closed behaviour, but it means a chronically throttled Jira
  source never auto-resolves findings.

**Required permissions.** A read-only account that can *Browse Projects* on every project in scope.
`GET /rest/api/3/myself` must answer for the connectivity check.

## Post-MVP connectors
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
| `rejected_bomb` | An archive whose *declared* expansion is hostile |
| `failed_timeout` | The parser did not finish; its child was killed |
| `failed_parse` | The parser raised, or crashed its child |

`is_hostile` separates the ones worth an operator's attention from an ordinary PNG;
`is_incomplete` separates outcomes that must make the scan partial from policy skips.

## Coverage assurance

Each fetch classifies every enumerated page, comment, attachment, record, or path exactly once as
scanned, skipped, or failed. A collection failure whose remaining cardinality is unknowable is a
separate scope gap; connectors must not invent an object count for it. Discovery similarly reports
configured/discovered scopes without claiming that an unrestricted source exposed objects the
credential could not enumerate.

The engine maps connector/parser detail onto the stable public reasons in
`iceberg_core.enums.CoverageReason` (permission denied, rate limited, size/output limits,
unsupported/binary/empty content, invalid responses/metadata, parser timeout/failure, connector
error, cancellation, and unreported legacy evidence). Parser enum values and exception messages do
not cross this boundary.

Skipped and failed objects receive a deterministic HMAC reference under the task's fingerprint
pepper. This makes the same gap correlatable between manifests without exporting its page id,
filename, path, scope value, or other source metadata. References are bounded at 10,000 per task;
exact aggregate counts continue and `gaps_omitted` makes truncation explicit.

Formats: text/code/config by extension (an allowlist, so a new binary format nobody denylisted is
not decoded as garbage), ZIP-backed office documents through their XML parts, and PDF through its
text layer. **No OCR** — a scanned page is honestly empty rather than reported as clean-and-scanned.
Archives are skipped rather than walked: recursing means recursing into archives inside archives,
and the bomb defence would have to be right at every level rather than the top one.

### The guards
**Scanned content is untrusted input**, and extraction parsers are the engine's largest attack
surface (`docs/security.md`, boundary 4). Five guards, each for a failure the others miss:

- **Size caps**, before any parsing — the cheapest check, and it eliminates "large file exhausts
  memory" whole.
- **Decompression-ratio limits.** Office documents are ZIP archives and a few kilobytes of zeros
  expands to gigabytes. The compressed size is exactly the number that tells you nothing, so the
  archive's *declared* sizes are checked first — total expansion, ratio, and member count. A header
  that lies the other way does not need a guard of its own: `zipfile` stops the read at the declared
  size and then fails the CRC, so the file ends as `failed_parse`, which is still `is_hostile`.
  Being merely *large* is not hostility — an honest part over what is left of the output budget is
  truncated and scanned like any oversized `.txt`, because rejecting it outright scans none of a
  spreadsheet whose whole point is that it might be full of credentials.
- **An address-space ceiling on the child.** A PDF is handed to the parser without a decompression
  guard — its streams are the format, not an archive — so the bound is `RLIMIT_AS` in the pool's
  initializer. Without it a Flate bomb allocates until the *cgroup* picks a victim, and on a
  memory-limited engine pod that can be the worker rather than the child: one hostile attachment
  becomes a pod restart, a reclaimed task, and a re-download of the same file.
- **Timeouts and crash isolation**, in a child process (`ExtractionSandbox`). A parser looping on a
  crafted cross-reference table cannot be caught with `try`, and cannot be bounded by a timer in the
  same process: `signal.alarm` only fires on the main thread, and a C extension in a tight loop
  never returns to the interpreter to notice it. A hang is a timeout and the child is killed; a
  segfault takes the child only. The pool is reused across files and replaced only when a child is
  actually lost.
- **Per-unit failure isolation** — the sum of the above. One hostile file does not stop readable
  neighbors from producing findings, but it makes the fetch task fail and the scan partial.
