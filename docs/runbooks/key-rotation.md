# Runbook: rotating the master key and the fingerprint pepper

Two different keys with two completely different rotation stories. Read the right half.

| | Master key (`ICEBERG_MASTER_KEY`) | Fingerprint pepper (`ICEBERG_FINGERPRINT_PEPPER_REF`) |
|---|---|---|
| Protects | Connector credentials, channel secrets, the pepper itself | Finding identity and secret hashes |
| Rotation is | A **re-seal** — mechanical, offline, minutes | A **re-scan** — needs every source scanned again |
| Downtime | None if done in order | None, but a window of days |
| Gets it wrong | Credentials undecryptable | Every triage decision detached from its finding |

Both are covered by tests: `packages/core/tests/test_secrets.py` for sealing, and
`apps/api/tests/test_pepper_rotation.py` for the rotation window — that file is the dry-run this
runbook's promises rest on.

---

## Before either: back up

```bash
kubectl get secret icebergsst-api -o yaml > api-secret-$(date +%F).yaml   # or your Secret manager
pg_dump "$ICEBERG_DATABASE_URL" > iceberg-$(date +%F).sql
```

**Losing the master key is not recoverable.** Every stored credential ref becomes undecryptable and
every source has to have its credential re-entered by hand. There is no support path for this; the
whole point of the design is that we cannot read them either.

---

## Master key rotation

Rotate when: the key may have been exposed, someone with access to it has left, or your policy says
so on a schedule.

Sealed refs are self-describing (`iceberg:1:<purpose>:<ciphertext>`) but carry no key id, so a
deployment reads refs with exactly one key. Rotation is therefore: decrypt everything with the old
key, re-encrypt with the new, swap the configuration. It touches three kinds of ref:

- `source.credential_ref` — connector credentials
- `notification_channel.config.secret_ref` — webhook signing secrets
- `ICEBERG_FINGERPRINT_PEPPER_REF` — the pepper's own sealed ref

### Procedure

1. **Generate a new key** and keep the old one to hand:

   ```bash
   NEW_KEY=$(python -m iceberg_core.secrets generate-master-key)
   ```

2. **Stop writes.** Scale the api to zero replicas, or put it behind maintenance. A credential
   written between the re-seal and the config swap would be sealed with the old key and lost.

   ```bash
   kubectl scale deploy/icebergsst-api --replicas=0
   ```

   Engines can keep running; they hold no refs. Tasks they cannot report will be reclaimed.

3. **Re-seal.** With both keys available, open each ref with the old key and seal it with the new.
   There is no bundled command for this — deliberately, because a tool that walks the database
   holding two master keys is a tool worth writing for your environment rather than shipping to
   everyone's:

   ```python
   # Run in a pod with both keys in the environment, against the database.
   from iceberg_core.secrets import EnvKeyBackend, SecretPurpose, decode_master_key
   old = EnvKeyBackend(decode_master_key(OLD_KEY))
   new = EnvKeyBackend(decode_master_key(NEW_KEY))

   for source in db.exec(select(Source).where(col(Source.credential_ref).is_not(None))):
       plaintext = old.open(source.credential_ref)
       source.credential_ref = new.seal(plaintext.get_secret_value())
       db.add(source)

   # Channels keep theirs inside `config`.
   for channel in db.exec(select(NotificationChannel)):
       ref = channel.config.get("secret_ref")
       if ref:
           channel.config = {**channel.config, "secret_ref": new.seal(old.open(ref).get_secret_value())}
           db.add(channel)

   # And the pepper — the same bytes, sealed under the new key. Print the new ref.
   print(new.seal_bytes(old.get_pepper(), purpose=SecretPurpose.PEPPER))
   db.commit()
   ```

   The pepper's **value does not change** here. This is a re-seal, not a pepper rotation; finding
   identities are untouched.

4. **Swap the configuration**: set `ICEBERG_MASTER_KEY` to the new key and
   `ICEBERG_FINGERPRINT_PEPPER_REF` to the ref printed above.

5. **Scale back up and verify** before discarding the old key:

   ```bash
   kubectl scale deploy/icebergsst-api --replicas=2
   # A source connectivity test decrypts a credential — the check that matters.
   curl -X POST .../api/v1/sources/$SOURCE_ID/test -H "Cookie: $SESSION"
   ```

   Confirm a scan runs and finds the findings it found before. Only then destroy the old key.

### If it goes wrong

Put the old key back. Re-sealing is idempotent per ref, so a partial run leaves some refs on each
key: refs that failed to open under the new key are the ones not yet re-sealed. Re-run the loop —
`open` with the old key raising `SealedRefError` on an already-migrated ref is how you tell them
apart.

---

## Fingerprint-pepper rotation

Rotate when: the pepper may have been exposed. A leaked pepper means an attacker with a database
dump can test guesses against `secret_hash` offline, which is the exact property the pepper exists
to remove.

### Why this is not a migration

A finding's identity is

```
secret_hash  = HMAC(pepper, secret)
fingerprint  = HMAC(pepper, connector ‖ locator ‖ rule ‖ secret_hash)
```

and **the plaintext secret is never stored** (ADR 0004). So the new values cannot be computed from
the old ones by anything with database access — the input is gone. Only an engine that currently
holds the secret, mid-scan, can compute its identity under a different key.

Rotating without accounting for that is quietly destructive: the next scan reports identities
nothing matches, every finding is created afresh, and reconciliation auto-resolves the originals.
Nothing is deleted, but every accepted risk, false positive and analyst note ends up attached to a
row nobody will ever look at again. `test_without_the_window_the_same_secret_ingests_as_a_new_finding`
demonstrates exactly this.

### The dual-pepper window

While `ICEBERG_PREVIOUS_FINGERPRINT_PEPPER_REF` is set alongside the current pepper:

1. Leases carry **both** peppers.
2. Engines report each finding twice over: `fingerprint`/`secret_hash` under the new pepper, and
   `previous_fingerprint`/`previous_secret_hash` under the old.
3. Ingest looks up the new fingerprint; on a miss it looks up the previous one. A hit is the *same*
   finding under a new key, so it is **re-keyed in place** — same row, same id, so the state,
   resolution, assignee, notes, suppression and the entire `finding_event` trail come with it.

### Procedure

1. **Generate a new pepper**, keeping the current ref:

   ```bash
   NEW_PEPPER_REF=$(ICEBERG_MASTER_KEY=$KEY python -m iceberg_core.secrets generate-pepper)
   ```

2. **Open the window.** The *current* ref becomes the previous one:

   ```yaml
   config:
     # ICEBERG_FINGERPRINT_PEPPER_REF     <- the new ref
     # ICEBERG_PREVIOUS_FINGERPRINT_PEPPER_REF  <- the ref that was current
   ```

   Roll the api. Nothing changes for anyone using the console.

3. **Scan every source.** Not "wait for the schedule" — check. Each scan re-keys the findings it
   sees; a source that is not scanned keeps its old identities, and closing the window would strand
   them.

   ```sql
   -- Sources with no completed scan since the window opened.
   SELECT s.name FROM source s
   WHERE NOT EXISTS (
     SELECT 1 FROM scan WHERE scan.source_id = s.id
       AND scan.status = 'completed' AND scan.started_at > '<window opened>'
   );
   ```

4. **Watch the re-key count fall to zero.** Each scan records `rekeyed` in `scan.counts`, and the
   API logs `finding_rekeyed` per finding:

   ```sql
   SELECT id, counts->>'rekeyed' FROM scan
   WHERE started_at > '<window opened>' ORDER BY started_at DESC;
   ```

   A source whose second scan in the window re-keys zero findings is done: the identities it holds
   are already the new ones.

5. **Close the window.** Unset `ICEBERG_PREVIOUS_FINGERPRINT_PEPPER_REF` and roll the api. Destroy
   the old pepper only after this.

### If a source cannot be scanned during the window

Keep the window open. There is no deadline, and the only cost of leaving it open is that engines
compute one extra HMAC per finding. Closing it while a source still holds old identities means that
source's next scan re-creates its findings as new and auto-resolves the originals — the failure
mode the window exists to avoid.

If the source is gone for good, its findings are historical either way. Close the window and accept
that a future scan of a resurrected source starts from nothing.

### Verifying, before you touch production

```bash
uv run pytest apps/api/tests/test_pepper_rotation.py -v
```

That suite is the dry-run: it builds a finding under an old pepper with a real analyst decision on
it, runs a scan's worth of ingest with both identities reported, and asserts the state, notes,
assignee and event trail are still attached to the same row afterwards — and, separately, that
without the window the same secret would have produced a duplicate.

---

## What rotating each key does *not* do

- **Master-key rotation does not change finding identities.** The pepper is re-sealed, not replaced.
- **Pepper rotation does not touch credentials.** They are sealed with the master key and are
  unaffected.
- **Neither rotates the session secret.** `ICEBERG_SESSION_SECRET` is independent; changing it logs
  everyone out immediately, which is the intended blast radius, and needs no window.
- **Neither rotates engine tokens.** Re-run `python -m iceberg_api mint-engine-token --name <name>`,
  which keeps the engine's id and replaces only the token.

---

## Correlation key rotation (ADR 0010)

The third key, with the cheapest rotation of all: `ICEBERG_CORRELATION_KEY_REF` derives exposure-
cluster ids from *stored* secret hashes, so a swap is a server-side recompute. No rescan, no
window, no engine involvement.

```bash
# 1. Generate a new sealed ref (needs the master key in the environment):
python -m iceberg_core.secrets generate-correlation-key

# 2. Swap ICEBERG_CORRELATION_KEY_REF to the new ref and restart the api.

# 3. Re-derive every stored id under the new key:
python -m iceberg_api reindex-correlation
```

The command is idempotent and restartable; run it again and `updated=0` confirms the rotation is
complete. Each run writes a `correlation.reindexed` audit event with its counts. Until the reindex
finishes, cluster views group under a mix of old and new ids — nothing is lost, just temporarily
split.

**During a pepper rotation** the same splitting happens for a different reason: the correlation id
is derived from `secret_hash`, which the pepper window rewrites row by row. Ingest recomputes the
id in the same statement that re-keys the hash, so clusters re-merge as the window completes — the
`rekeyed` counter falling to zero is the same signal it always was. No extra step is needed.

- **Correlation-key rotation does not touch finding identities, credentials, or the pepper.**
  It invalidates only the cluster grouping, which it immediately rebuilds.
