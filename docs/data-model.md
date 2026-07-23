# Data model

SQLModel entities backing the control plane. This is the design sketch; exact columns/indexes are
finalized in the schema implementation issue (M0). All tables are single-org (no `tenant_id`).

## Identity & access

### User
OIDC-backed user.
- `id`, `oidc_subject` (unique), `email`, `display_name`
- `role`: enum `admin | analyst | viewer`
- `created_at`, `last_login_at`, `disabled`

## Sources & scheduling

### Source
A scan target.
- `id`, `name`, `type`: enum `confluence | jira | smb` (MVP: confluence)
- `connection`: JSON (base URL, space/path scope filters, etc.)
- `credential_ref`: opaque handle into the secret store (never the raw secret)
- `enabled`, `created_by`, `created_at`, `updated_at`

### Schedule
- `id`, `source_id` (FK), `cron` (5-field expr), `enabled`
- `next_run_at`, `last_run_at`

## Scans

### Scan
One scan run of a Source.
- `id`, `source_id` (FK), `trigger`: enum `manual | scheduled`
- `status`: enum `queued | running | completed | partial | failed | cancelled`
- `rulepack_version`, `counts`: JSON (units scanned, findings new/resolved/…)
- `started_at`, `finished_at`, `error`

### ScanTask
A unit of work dispatched to one engine (e.g. a Confluence space or page batch).
- `id`, `scan_id` (FK), `spec`: JSON (what to fetch)
- `status`: enum `queued | leased | running | completed | failed`
- `engine_id` (FK, nullable), `lease_expires_at`, `heartbeat_at`, `attempts`
- `started_at`, `finished_at`, `error`

## Findings & triage

### Finding
- `id`, `scan_id` (FK, discovering scan), `source_id` (FK)
- `fingerprint` (unique per source — see ADR 0006), indexed
- `rule_id`, `rulepack_version`
- `resource_locator`: JSON (page id, URL, attachment name, line/offset)
- `redacted_snippet` (masked context; **no plaintext**)
- `secret_hash` (salted/peppered), `entropy`, `confidence`, `severity`
- `state`: enum `open | false_positive | accepted_risk | resolved`
- `resolution`: enum `null | manual | auto` (auto = disappeared on re-scan)
- `assignee_id` (FK User, nullable), `notes`
- `first_seen_scan_id`, `last_seen_scan_id`, `created_at`, `updated_at`

### FindingEvent
Append-only audit trail.
- `id`, `finding_id` (FK), `actor_id` (FK User, nullable for system)
- `kind`: enum `state_change | assign | comment | suppressed | reopened`
- `from_value`, `to_value`, `comment`, `created_at`

### Suppression
Analyst-managed allowlist (ADR 0008).
- `id`, `scope`: enum `path_glob | fingerprint | rule`
- `pattern` (glob / fingerprint / rule_id), `source_id` (FK, nullable = global)
- `reason`, `created_by` (FK User), `expires_at` (nullable), `created_at`

## Engines & notifications

### Engine
Registered worker.
- `id`, `name`, `token_hash`, `version`
- `status`: enum `active | draining | offline`, `last_heartbeat_at`, `registered_at`

### NotificationChannel
- `id`, `type`: enum `email | webhook`
- `config`: JSON (SMTP recipients / webhook URL)
- `event_filter`: JSON (e.g. min severity, source ids), `enabled`

## Key relationships & indexes
- `Finding.fingerprint` unique within `source_id`; primary reconciliation lookup.
- `ScanTask.status + lease_expires_at` indexed for lease reclamation of dead engines.
- `Finding.state + source_id` indexed for the findings list/filter view.
